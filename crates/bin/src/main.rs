//! `pakiz` — terminal paket analizörü (Aşama 1: ham sayaç).

use std::time::Duration;

use anyhow::{bail, Context, Result};
use clap::Parser;
use pakiz_capture::{list_interfaces, start_capture, CaptureConfig, CaptureMode};

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
    /// Ham paket sayacı modu (şimdilik varsayılan ve tek mod)
    #[arg(long)]
    count: bool,
    /// Promiscuous modu açma
    #[arg(long)]
    no_promisc: bool,
    /// `TPACKET_V3` yerine `recvfrom` kullan
    #[arg(long)]
    force_recv: bool,
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

async fn run_count(iface: String, cli: &Cli) -> Result<()> {
    let mut cfg = CaptureConfig::new(iface);
    cfg.promisc = !cli.no_promisc;
    cfg.force_recv = cli.force_recv;
    let (rx, handle) = start_capture(&cfg)?;
    match handle.mode() {
        CaptureMode::MmapV3 => eprintln!("yakalama yolu: TPACKET_V3 mmap ring"),
        CaptureMode::Recv(why) => eprintln!("yakalama yolu: recvfrom (V3 kullanılamadı: {why})"),
    }

    let (mut packets, mut bytes) = (0u64, 0u64);
    let mut tick = tokio::time::interval(Duration::from_secs(1));
    tick.tick().await;
    let ctrl_c = tokio::signal::ctrl_c();
    tokio::pin!(ctrl_c);
    loop {
        tokio::select! {
            r = &mut ctrl_c => { r.context("Ctrl-C dinlenemedi")?; break; }
            _ = tick.tick() => {
                for p in rx.try_iter() {
                    packets += 1;
                    bytes += u64::from(p.orig_len);
                }
                let st = handle.stats()?;
                println!("paket: {packets}, bayt: {bytes}, düşen: {}", st.dropped + st.app_dropped);
            }
        }
    }
    handle.stop().context("yakalama durdurulamadı")?;
    eprintln!("durduruldu (promisc kapatıldı)");
    Ok(())
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    if cli.list_interfaces {
        return print_interfaces();
    }
    let Some(iface) = cli.interface.clone() else {
        bail!("arayüz gerekli: -i <arayüz> (listelemek için --list-interfaces)");
    };
    let _ = cli.count; // Aşama 1'de tek mod sayaç
    run_count(iface, &cli).await
}
