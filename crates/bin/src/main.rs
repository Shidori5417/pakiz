//! `pakiz` — terminal paket analizörü (varsayılan TUI, `--no-tui` satır çıktısı, `--count` sayaç).

use std::time::{Duration, SystemTime};

use anyhow::{bail, Context, Result};
use clap::Parser;
use pakiz_capture::{list_interfaces, start_capture, CaptureConfig, CaptureHandle, CaptureMode};
use pakiz_dissect::{RawPacket, Registry};
use pakiz_tui::{App, PacketSource, Tui};
use tokio::signal::unix::{signal, SignalKind};

#[derive(Debug, Parser)]
#[command(name = "pakiz", version, about = "Linux için terminal paket analizörü")]
#[allow(clippy::struct_excessive_bools)]
struct Cli {
    /// Yakalanacak arayüz
    #[arg(short = 'i', long = "interface")]
    interface: Option<String>,
    /// Arayüzleri listele ve çık
    #[arg(long)]
    list_interfaces: bool,
    /// Ham paket sayacı modu
    #[arg(long, conflicts_with = "no_tui")]
    count: bool,
    /// Her paketi tek satır yaz (TUI yokken varsayılan)
    #[arg(long)]
    no_tui: bool,
    /// Promiscuous modu açma
    #[arg(long)]
    no_promisc: bool,
    /// `TPACKET_V3` yerine `recvfrom` kullan
    #[arg(long)]
    force_recv: bool,
    /// TUI'de bellekte tutulacak en fazla paket (eskiler düşer)
    #[arg(long, default_value_t = pakiz_tui::PacketStore::DEFAULT_MAX)]
    max_packets: usize,
}

/// Canlı yakalama kaynağı: kanal + kernel istatistikleri.
struct LiveSource {
    name: String,
    rx: crossbeam_channel::Receiver<RawPacket>,
    handle: CaptureHandle,
}

impl PacketSource for LiveSource {
    fn name(&self) -> &str {
        &self.name
    }
    fn try_next(&mut self) -> Option<RawPacket> {
        self.rx.try_recv().ok()
    }
    fn dropped(&self) -> u64 {
        self.handle.stats().map_or(0, |s| s.dropped + s.app_dropped)
    }
}

fn print_interfaces() -> Result<()> {
    println!("{:>4}  {:<16} {:<5} MAC", "IDX", "AD", "DURUM");
    for i in list_interfaces().context("arayüzler listelenemedi")? {
        println!(
            "{:>4}  {:<16} {:<5} {}",
            i.index,
            i.name,
            if i.up { "UP" } else { "DOWN" },
            i.mac.as_deref().unwrap_or("-")
        );
    }
    Ok(())
}

fn open(
    iface: String,
    cli: &Cli,
    quiet: bool,
) -> Result<(crossbeam_channel::Receiver<RawPacket>, CaptureHandle)> {
    let mut cfg = CaptureConfig::new(iface);
    cfg.promisc = !cli.no_promisc;
    cfg.force_recv = cli.force_recv;
    let (rx, handle) = start_capture(&cfg)?;
    match handle.mode() {
        _ if quiet => {}
        CaptureMode::MmapV3 => eprintln!("yakalama yolu: TPACKET_V3 mmap ring"),
        CaptureMode::Recv(why) => eprintln!("yakalama yolu: recvfrom (V3 kullanılamadı: {why})"),
    }
    Ok((rx, handle))
}

/// Ctrl-C veya SIGTERM gelene kadar `on_tick`'i `period` aralıkla çağırır, sonra yakalamayı durdurur.
async fn run_loop(
    handle: CaptureHandle,
    period: Duration,
    mut on_tick: impl FnMut(&CaptureHandle) -> Result<()>,
) -> Result<()> {
    let mut term = signal(SignalKind::terminate()).context("SIGTERM dinlenemedi")?;
    let mut tick = tokio::time::interval(period);
    tick.tick().await;
    let ctrl_c = tokio::signal::ctrl_c();
    tokio::pin!(ctrl_c);
    loop {
        tokio::select! {
            r = &mut ctrl_c => { r.context("Ctrl-C dinlenemedi")?; break; }
            _ = term.recv() => break,
            _ = tick.tick() => on_tick(&handle)?,
        }
    }
    on_tick(&handle)?;
    handle.stop().context("yakalama durdurulamadı")?;
    eprintln!("durduruldu (promisc kapatıldı)");
    Ok(())
}

async fn run_count(iface: String, cli: &Cli) -> Result<()> {
    let (rx, handle) = open(iface, cli, false)?;
    let (mut packets, mut bytes) = (0u64, 0u64);
    run_loop(handle, Duration::from_secs(1), |h| {
        for p in rx.try_iter() {
            packets += 1;
            bytes += u64::from(p.orig_len);
        }
        let st = h.stats()?;
        println!(
            "paket: {packets}, bayt: {bytes}, düşen: {}",
            st.dropped + st.app_dropped
        );
        Ok(())
    })
    .await
}

async fn run_lines(iface: String, cli: &Cli) -> Result<()> {
    let (rx, handle) = open(iface, cli, false)?;
    let reg = Registry::default();
    let mut number = 0u64;
    let mut first: Option<SystemTime> = None;
    run_loop(handle, Duration::from_millis(20), |_| {
        for p in rx.try_iter() {
            number += 1;
            let t0 = *first.get_or_insert(p.ts);
            let rel = p.ts.duration_since(t0).unwrap_or_default().as_secs_f64();
            let s = reg.dissect(&p).summary;
            println!(
                "{number:>6} {rel:>11.6} {} → {} {} {} {}",
                s.src, s.dst, s.protocol, s.len, s.info
            );
        }
        Ok(())
    })
    .await
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    if cli.list_interfaces {
        return print_interfaces();
    }
    if !cli.count && !cli.no_tui {
        return run_tui(&cli);
    }
    let Some(iface) = cli.interface.clone() else {
        bail!("arayüz gerekli: -i <arayüz> (listelemek için --list-interfaces)");
    };
    if cli.count {
        run_count(iface, &cli).await
    } else {
        run_lines(iface, &cli).await
    }
}

/// TUI modu; `-i` yoksa önce arayüz seçtirir. `Tui` drop edilince terminal geri yüklenir.
fn run_tui(cli: &Cli) -> Result<()> {
    let mut tui = Tui::new().context("terminal hazırlanamadı")?;
    let iface = if let Some(i) = cli.interface.clone() {
        i
    } else {
        let ifaces = list_interfaces().context("arayüzler listelenemedi")?;
        let items: Vec<String> = ifaces
            .iter()
            .map(|i| {
                format!(
                    "{:<16} {:<5} {}",
                    i.name,
                    if i.up { "UP" } else { "DOWN" },
                    i.mac.as_deref().unwrap_or("-")
                )
            })
            .collect();
        let Some(chosen) = tui.pick_interface(&items)?.and_then(|idx| ifaces.get(idx)) else {
            return Ok(());
        };
        chosen.name.clone()
    };
    let (rx, handle) = open(iface.clone(), cli, true)?;
    let src = LiveSource {
        name: iface,
        rx,
        handle,
    };
    let mut app = App::new(Box::new(src), cli.max_packets);
    tui.run(&mut app)?;
    Ok(())
}
