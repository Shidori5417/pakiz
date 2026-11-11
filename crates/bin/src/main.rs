//! `pakiz` — terminal paket analizörü (varsayılan TUI, `--no-tui` satır çıktısı, `--count` sayaç).

#![cfg_attr(test, allow(clippy::unwrap_used))]

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, SystemTime};

use anyhow::{bail, Context, Result};
use clap::Parser;
use pakiz_capture::{list_interfaces, start_capture, CaptureConfig, CaptureHandle, CaptureMode};
use pakiz_dissect::{RawPacket, Registry};
use pakiz_filter::{bpf, FieldCatalog, Filter, FilterError};
use pakiz_storage::{CaptureReader, CaptureWriter, Format, IndexedFile};
use pakiz_tui::{App, PacketSource, Tui};
use tokio::signal::unix::{signal, SignalKind};

#[derive(Debug, Parser)]
#[command(name = "pakiz", version, about = "Linux için terminal paket analizörü")]
#[allow(clippy::struct_excessive_bools)]
struct Cli {
    /// Yakalanacak arayüz
    #[arg(short = 'i', long = "interface")]
    interface: Option<String>,
    /// pcap/pcapng dosyasından oku
    #[arg(short = 'r', long = "read", conflicts_with_all = ["interface", "count"])]
    read: Option<PathBuf>,
    /// Paketleri dosyaya yaz (`.pcapng` → pcapng, diğerleri pcap)
    #[arg(short = 'w', long = "write")]
    write: Option<PathBuf>,
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
    /// Display filter (ör. `tcp.port == 443`): TUI başlangıç filtresi; `--no-tui` ve
    /// `-r ... -w` dönüşümünde yalnızca eşleşenler
    #[arg(short = 'Y', long = "display-filter", conflicts_with = "count")]
    display_filter: Option<String>,
    /// Yakalama filtresi, kernel'de klasik BPF (ör. `tcp port 80 and host 10.0.0.1`)
    #[arg(short = 'f', long = "capture-filter", conflicts_with = "read")]
    capture_filter: Option<String>,
    /// TUI'de bellekte tutulacak en fazla paket (eskiler düşer)
    #[arg(long, default_value_t = pakiz_tui::PacketStore::DEFAULT_MAX)]
    max_packets: usize,
}

/// Canlı yakalama kaynağı: kanal + kernel istatistikleri.
struct LiveSource {
    name: String,
    rx: crossbeam_channel::Receiver<RawPacket>,
    handle: CaptureHandle,
    /// Yazıcı thread'i ile UI arasındaki kanalda düşen paket (dosyaya yine yazılır).
    ui_dropped: Arc<AtomicU64>,
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
            + self.ui_dropped.load(Ordering::Relaxed)
    }
}

fn create_writer(path: &Path) -> Result<Box<dyn CaptureWriter + Send>> {
    pakiz_storage::create(path, Format::from_path(path))
        .with_context(|| format!("{} oluşturulamadı", path.display()))
}

/// Yakalanan paketleri ayrı bir thread'de dosyaya yazar ve UI'ya iletir.
/// UI kanalı doluysa paket UI için düşer ama dosyaya yazılır. Kaynak kanal
/// kapanınca (yakalama durunca) tamponu boşaltıp yazılan sayıyı döner.
fn spawn_writer(
    rx: crossbeam_channel::Receiver<RawPacket>,
    mut w: Box<dyn CaptureWriter + Send>,
    ui_dropped: Arc<AtomicU64>,
) -> Result<(
    crossbeam_channel::Receiver<RawPacket>,
    JoinHandle<Result<u64>>,
)> {
    let (tx, ui_rx) = crossbeam_channel::bounded(65_536);
    let h = std::thread::Builder::new()
        .name("pakiz-writer".into())
        .spawn(move || -> Result<u64> {
            let mut n = 0u64;
            let mut res = Ok(());
            for p in rx {
                if res.is_ok() {
                    res = w.write_packet(&p);
                    n += 1;
                }
                if tx.try_send(p).is_err() {
                    ui_dropped.fetch_add(1, Ordering::Relaxed);
                }
            }
            res.and_then(|()| w.flush()).context("dosyaya yazılamadı")?;
            Ok(n)
        })
        .context("yazıcı thread'i başlatılamadı")?;
    Ok((ui_rx, h))
}

/// Filtre hatasını kaynak + konum işaretiyle biçimler.
fn filter_error(kind: &str, src: &str, e: &FilterError) -> anyhow::Error {
    let col = src.get(..e.span.start).map_or(0, |s| s.chars().count());
    let width = src
        .get(e.span.clone())
        .map_or(1, |s| s.chars().count().max(1));
    anyhow::anyhow!(
        "{kind} hatası: {} (sütun {})\n  {src}\n  {}{}",
        e.msg,
        col + 1,
        " ".repeat(col),
        "^".repeat(width)
    )
}

fn display_filter(cli: &Cli) -> Result<Option<Filter>> {
    cli.display_filter
        .as_deref()
        .filter(|s| !s.trim().is_empty())
        .map(|src| {
            Filter::compile(src, &FieldCatalog::default())
                .map_err(|e| filter_error("display filter (-Y)", src, &e))
        })
        .transpose()
}

/// `-f` ifadesini derleyip kernel'in `struct sock_filter` dizisine çevirir.
fn capture_filter(src: &str) -> Result<Vec<pakiz_capture::sock_filter>> {
    let prog = bpf::compile(src).map_err(|e| filter_error("yakalama filtresi (-f)", src, &e))?;
    Ok(to_sock_filter(&prog))
}

fn to_sock_filter(prog: &[bpf::SockFilter]) -> Vec<pakiz_capture::sock_filter> {
    prog.iter()
        .map(|i| pakiz_capture::sock_filter {
            code: i.code,
            jt: i.jt,
            jf: i.jf,
            k: i.k,
        })
        .collect()
}

/// Paketi bir kez ayrıştırır; filtre yoksa veya eşleşirse satırı yazar ve `true` döner.
fn emit(
    reg: &Registry,
    filter: Option<&Filter>,
    print: bool,
    number: u64,
    first: &mut Option<SystemTime>,
    p: &RawPacket,
) -> bool {
    let d = reg.dissect_numbered(p, Some(number));
    if filter.is_some_and(|f| !f.matches(&d, p)) {
        return false;
    }
    if print {
        print_line(&d.summary, number, first, p);
    }
    true
}

fn print_line(
    s: &pakiz_dissect::Summary,
    number: u64,
    first: &mut Option<SystemTime>,
    p: &RawPacket,
) {
    let t0 = *first.get_or_insert(p.ts);
    let rel = p.ts.duration_since(t0).unwrap_or_default().as_secs_f64();
    println!(
        "{number:>6} {rel:>11.6} {} → {} {} {} {}",
        s.src, s.dst, s.protocol, s.len, s.info
    );
}

/// `-r` (TUI'siz): satır yaz (`--no-tui`) ve/veya `-w` ile başka dosyaya dönüştür.
fn run_read(path: &Path, cli: &Cli) -> Result<()> {
    let mut reader =
        CaptureReader::open(path).with_context(|| format!("{} açılamadı", path.display()))?;
    let mut writer = cli.write.as_deref().map(create_writer).transpose()?;
    let filter = display_filter(cli)?;
    let reg = Registry::default();
    let (mut number, mut written) = (0u64, 0u64);
    let mut first = None;
    while let Some(p) = reader.next_packet().context("dosya okunamadı")? {
        number += 1;
        if !emit(&reg, filter.as_ref(), cli.no_tui, number, &mut first, &p) {
            continue;
        }
        if let Some(w) = writer.as_mut() {
            w.write_packet(&p).context("dosyaya yazılamadı")?;
            written += 1;
        }
    }
    if let (Some(w), Some(out)) = (writer.as_mut(), cli.write.as_deref()) {
        w.flush().context("dosyaya yazılamadı")?;
        eprintln!("{written} paket yazıldı: {}", out.display());
    }
    Ok(())
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
    cfg.filter = cli
        .capture_filter
        .as_deref()
        .map(capture_filter)
        .transpose()?;
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
    let mut writer = cli.write.as_deref().map(create_writer).transpose()?;
    let (rx, handle) = open(iface, cli, false)?;
    let (mut packets, mut bytes) = (0u64, 0u64);
    run_loop(handle, Duration::from_secs(1), |h| {
        for p in rx.try_iter() {
            packets += 1;
            bytes += u64::from(p.orig_len);
            if let Some(w) = writer.as_mut() {
                w.write_packet(&p).context("dosyaya yazılamadı")?;
            }
        }
        if let Some(w) = writer.as_mut() {
            w.flush().context("dosyaya yazılamadı")?;
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
    let filter = display_filter(cli)?;
    let mut writer = cli.write.as_deref().map(create_writer).transpose()?;
    let (rx, handle) = open(iface, cli, false)?;
    let reg = Registry::default();
    let mut number = 0u64;
    let mut first: Option<SystemTime> = None;
    run_loop(handle, Duration::from_millis(20), |_| {
        for p in rx.try_iter() {
            number += 1;
            if !emit(&reg, filter.as_ref(), true, number, &mut first, &p) {
                continue;
            }
            if let Some(w) = writer.as_mut() {
                w.write_packet(&p).context("dosyaya yazılamadı")?;
            }
        }
        if let Some(w) = writer.as_mut() {
            w.flush().context("dosyaya yazılamadı")?;
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
    // Terminal hazırlanmadan önce filtre hatalarını bildir.
    display_filter(&cli)?;
    if let Some(path) = cli.read.as_deref() {
        if !cli.no_tui && cli.write.is_none() {
            return run_tui_file(path, &cli);
        }
        return run_read(path, &cli);
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
    if let Some(src) = cli.capture_filter.as_deref() {
        capture_filter(src)?;
    }
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
    let writer = cli.write.as_deref().map(create_writer).transpose()?;
    let (rx, handle) = open(iface.clone(), cli, true)?;
    let ui_dropped = Arc::new(AtomicU64::new(0));
    let (rx, writer) = match writer {
        Some(w) => {
            let (rx, h) = spawn_writer(rx, w, Arc::clone(&ui_dropped))?;
            (rx, Some(h))
        }
        None => (rx, None),
    };
    let src = LiveSource {
        name: iface,
        rx,
        handle,
        ui_dropped,
    };
    let mut app = App::new(Box::new(src), cli.max_packets);
    set_initial_filter(&mut app, cli)?;
    let res = tui.run(&mut app);
    // Kaynağı bırakmak yakalamayı durdurur; yazıcı kanal kapanınca bitip flush eder.
    drop(app);
    drop(tui);
    if let Some(h) = writer {
        let n = h
            .join()
            .map_err(|_| anyhow::anyhow!("yazıcı thread'i panikledi"))??;
        if let Some(out) = cli.write.as_deref() {
            eprintln!("{n} paket yazıldı: {}", out.display());
        }
    }
    res.context("TUI hatası")
}

/// `-r` ile TUI: dosya indeksli açılır, paketler gerektiğinde diskten okunur.
fn run_tui_file(path: &Path, cli: &Cli) -> Result<()> {
    let file = IndexedFile::open(path).with_context(|| format!("{} açılamadı", path.display()))?;
    let mut app = App::from_file(file, path.display().to_string());
    set_initial_filter(&mut app, cli)?;
    let mut tui = Tui::new().context("terminal hazırlanamadı")?;
    tui.run(&mut app)?;
    Ok(())
}

fn set_initial_filter(app: &mut App, cli: &Cli) -> Result<()> {
    if let Some(src) = cli.display_filter.as_deref() {
        app.set_filter(src)
            .map_err(|e| filter_error("display filter (-Y)", src, &e))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capture_filter_converts_to_kernel_struct() {
        let prog = bpf::compile("icmp").unwrap();
        let k = capture_filter("icmp").unwrap();
        assert_eq!(k.len(), prog.len());
        for (a, b) in prog.iter().zip(&k) {
            assert_eq!((a.code, a.jt, a.jf, a.k), (b.code, b.jt, b.jf, b.k));
        }
        let e = capture_filter("tcp port").unwrap_err().to_string();
        assert!(
            e.contains("yakalama filtresi (-f)") && e.contains('^'),
            "{e}"
        );
    }

    #[test]
    fn display_filter_error_has_position() {
        let cli = Cli::parse_from(["pakiz", "-Y", "ip.ttl =="]);
        let e = display_filter(&cli).unwrap_err().to_string();
        assert!(
            e.contains("display filter (-Y) hatası") && e.contains("sütun"),
            "{e}"
        );
        let cli = Cli::parse_from(["pakiz", "-Y", "icmp.type == 8"]);
        assert!(display_filter(&cli).unwrap().is_some());
    }

    /// Canlı: `lo` üzerinde `udp and port 47999` filtresi kernel'e bağlanır; başka
    /// porta giden UDP gelmez. Yetki yoksa (`CAP_NET_RAW`) atlanır; ör.
    /// `unshare -rn sh -c 'ip link set lo up; cargo test -p pakiz-bin'`.
    #[test]
    fn capture_filter_attached_live() {
        let mut cfg = CaptureConfig::new("lo");
        cfg.promisc = false;
        cfg.force_recv = true;
        cfg.filter = Some(capture_filter("udp and port 47999").unwrap());
        let Ok((rx, handle)) = start_capture(&cfg) else {
            eprintln!("atlandı: lo üzerinde yakalama izni yok");
            return;
        };
        let sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        for _ in 0..3 {
            sock.send_to(b"x", "127.0.0.1:47998").unwrap();
            sock.send_to(b"y", "127.0.0.1:47999").unwrap();
        }
        std::thread::sleep(Duration::from_millis(300));
        let reg = Registry::default();
        let got: Vec<String> = rx
            .try_iter()
            .map(|p| reg.dissect(&p).summary.info)
            .collect();
        handle.stop().unwrap();
        assert!(!got.is_empty(), "filtreye uyan paket gelmedi");
        assert!(got.iter().all(|i| i.contains("47999")), "{got:?}");
    }
}
