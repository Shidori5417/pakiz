//! pakiz-capture: libpcap'siz `AF_PACKET` yakalama (`TPACKET_V3` mmap, yoksa `recvfrom`).

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

mod error;
mod iface;
mod socket;

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

use crossbeam_channel::{Receiver, TrySendError};
use pakiz_dissect::RawPacket;

pub use error::{CaptureError, Result};
pub use iface::{interface_index, list_interfaces, Interface};
pub use socket::{sock_filter, KernelStats, PacketSocket};

/// Yakalama yapılandırması.
#[derive(Debug, Clone)]
pub struct CaptureConfig {
    pub interface: String,
    pub promisc: bool,
    /// `TPACKET_V3`'ü atla, doğrudan `recvfrom` kullan.
    pub force_recv: bool,
    /// Klasik BPF yakalama filtresi.
    pub filter: Option<Vec<sock_filter>>,
    pub channel_capacity: usize,
}

impl CaptureConfig {
    #[must_use]
    pub fn new(interface: impl Into<String>) -> Self {
        Self {
            interface: interface.into(),
            promisc: true,
            force_recv: false,
            filter: None,
            channel_capacity: 65_536,
        }
    }
}

/// Kullanılan okuma yolu.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CaptureMode {
    MmapV3,
    /// `recvfrom`; içerik: V3 neden kurulamadı.
    Recv(String),
}

/// Toplam sayaçlar.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CaptureStats {
    /// Kernel'in sokete teslim ettiği.
    pub received: u64,
    /// Kernel'de düşen.
    pub dropped: u64,
    /// Kanal dolu olduğu için uygulamada düşen.
    pub app_dropped: u64,
}

/// Çalışan yakalamanın tutamacı. Drop edilince durdurur.
pub struct CaptureHandle {
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<Result<()>>>,
    socket: Arc<PacketSocket>,
    mode: CaptureMode,
    totals: Mutex<KernelStats>,
    app_dropped: Arc<AtomicU64>,
}

impl CaptureHandle {
    #[must_use]
    pub fn mode(&self) -> &CaptureMode {
        &self.mode
    }

    /// Paylaşılan stop bayrağı.
    #[must_use]
    pub fn stop_flag(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.stop)
    }

    /// Çalışma sırasında BPF filtresi değiştir.
    ///
    /// # Errors
    /// Kernel reddederse.
    pub fn attach_filter(&self, prog: &[sock_filter]) -> Result<()> {
        self.socket.attach_filter(prog)
    }

    /// Kümülatif istatistikler (`PACKET_STATISTICS`).
    ///
    /// # Errors
    /// `getsockopt` başarısızsa.
    pub fn stats(&self) -> Result<CaptureStats> {
        let d = self.socket.stats_delta()?;
        let mut t = self
            .totals
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        t.received += d.received;
        t.dropped += d.dropped;
        Ok(CaptureStats {
            received: t.received,
            dropped: t.dropped,
            app_dropped: self.app_dropped.load(Ordering::Relaxed),
        })
    }

    /// Durdurur, promisc'i kapatır, thread'i bekler.
    ///
    /// # Errors
    /// Yakalama thread'i hatayla bittiyse.
    pub fn stop(mut self) -> Result<()> {
        self.shutdown()
    }

    fn shutdown(&mut self) -> Result<()> {
        self.stop.store(true, Ordering::Relaxed);
        let promisc = self.socket.set_promisc(false);
        let res = match self.thread.take() {
            Some(t) => t.join().map_err(|_| CaptureError::ThreadPanicked)?,
            None => Ok(()),
        };
        res.and(promisc)
    }
}

impl Drop for CaptureHandle {
    fn drop(&mut self) {
        let _ = self.shutdown();
    }
}

fn is_loopback(name: &str) -> bool {
    list_interfaces().is_ok_and(|l| l.iter().any(|i| i.name == name && i.loopback))
}

/// Yakalamayı ayrı bir OS thread'inde başlatır.
///
/// # Errors
/// Arayüz yok, yetki yok ya da soket kurulamazsa.
pub fn start_capture(cfg: &CaptureConfig) -> Result<(Receiver<RawPacket>, CaptureHandle)> {
    let ifindex = interface_index(&cfg.interface)?;
    let sock = Arc::new(PacketSocket::open(ifindex)?);
    if let Some(f) = &cfg.filter {
        sock.attach_filter(f)?;
    }
    let (ring, mode) = if cfg.force_recv {
        (None, CaptureMode::Recv("force_recv".into()))
    } else {
        match socket::Ring::setup(&sock) {
            Ok(r) => (Some(r), CaptureMode::MmapV3),
            Err(e @ CaptureError::Permission { .. }) => return Err(e),
            Err(e) => (None, CaptureMode::Recv(e.to_string())),
        }
    };
    sock.bind()?;
    if cfg.promisc {
        sock.set_promisc(true)?;
    }
    // lo'da her paket hem OUTGOING hem gelen olarak görünür; libpcap gibi birini at.
    let skip_outgoing = is_loopback(&cfg.interface);

    let (tx, rx) = crossbeam_channel::bounded(cfg.channel_capacity.max(1));
    let stop = Arc::new(AtomicBool::new(false));
    let app_dropped = Arc::new(AtomicU64::new(0));
    let thread = {
        let sock = Arc::clone(&sock);
        let stop = Arc::clone(&stop);
        let app_dropped = Arc::clone(&app_dropped);
        std::thread::Builder::new()
            .name("pakiz-capture".into())
            .spawn(move || {
                let emit = |p: RawPacket| match tx.try_send(p) {
                    Ok(()) => {}
                    Err(TrySendError::Full(_)) => {
                        app_dropped.fetch_add(1, Ordering::Relaxed);
                    }
                    Err(TrySendError::Disconnected(_)) => stop.store(true, Ordering::Relaxed),
                };
                match ring {
                    Some(r) => r.run(&sock, skip_outgoing, &stop, emit),
                    None => sock.recv_loop(skip_outgoing, &stop, emit),
                }
            })
            .map_err(|source| CaptureError::Io {
                op: "thread spawn",
                source,
            })?
    };
    Ok((
        rx,
        CaptureHandle {
            stop,
            thread: Some(thread),
            socket: sock,
            mode,
            totals: Mutex::new(KernelStats::default()),
            app_dropped,
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_defaults() {
        let c = CaptureConfig::new("lo");
        assert_eq!(c.interface, "lo");
        assert!(c.filter.is_none() && !c.force_recv);
    }

    #[test]
    fn missing_interface_error() {
        let Err(e) = start_capture(&CaptureConfig::new("pakizyok0")) else {
            panic!("olmayan arayüz açıldı");
        };
        assert!(matches!(e, CaptureError::NoSuchInterface(_)));
        assert_eq!(e.to_string(), "arayüz bulunamadı: pakizyok0");
    }
}
