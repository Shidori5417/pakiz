use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::Path;
use std::time::{Duration, UNIX_EPOCH};

use pakiz_dissect::RawPacket;

use crate::{Error, Format, Result, LINKTYPE_ETHERNET};

const SNAPLEN: u32 = 262_144;

/// Yazılan zaman damgası çözünürlüğü.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TsResolution {
    /// Mikrosaniye.
    Micro,
    /// Nanosaniye.
    #[default]
    Nano,
}

/// Ortak yazıcı arayüzü.
pub trait CaptureWriter {
    /// Bir paket yazar.
    ///
    /// # Errors
    /// G/Ç hatası ya da 4 GiB'tan büyük paket.
    fn write_packet(&mut self, pkt: &RawPacket) -> Result<()>;
    /// Tamponu boşaltır.
    ///
    /// # Errors
    /// G/Ç hatası.
    fn flush(&mut self) -> Result<()>;
}

/// Yolu açıp verilen biçimde yazıcı döner (bkz. [`Format::from_path`]).
///
/// # Errors
/// Dosya oluşturulamazsa.
pub fn create(path: impl AsRef<Path>, format: Format) -> Result<Box<dyn CaptureWriter + Send>> {
    let w = BufWriter::new(File::create(path)?);
    Ok(match format {
        Format::Pcap => Box::new(PcapWriter::new(w)?),
        Format::Pcapng => Box::new(PcapngWriter::new(w)?),
    })
}

fn since_epoch(pkt: &RawPacket) -> Duration {
    pkt.ts.duration_since(UNIX_EPOCH).unwrap_or(Duration::ZERO)
}

fn lens(pkt: &RawPacket) -> Result<(u32, u32)> {
    let cap = u32::try_from(pkt.data.len()).map_err(|_| Error::TooLarge(pkt.data.len()))?;
    Ok((cap, pkt.orig_len.max(cap)))
}

/// Klasik pcap yazıcı (little-endian, linktype 1).
pub struct PcapWriter<W: Write> {
    w: W,
    res: TsResolution,
}

impl<W: Write> PcapWriter<W> {
    /// Nanosaniye magic'iyle global başlığı yazar.
    ///
    /// # Errors
    /// G/Ç hatası.
    pub fn new(w: W) -> Result<Self> {
        Self::with_resolution(w, TsResolution::Nano)
    }

    /// Belirtilen çözünürlükle global başlığı yazar.
    ///
    /// # Errors
    /// G/Ç hatası.
    pub fn with_resolution(mut w: W, res: TsResolution) -> Result<Self> {
        let magic: u32 = match res {
            TsResolution::Micro => 0xa1b2_c3d4,
            TsResolution::Nano => 0xa1b2_3c4d,
        };
        let mut h = Vec::with_capacity(24);
        h.extend_from_slice(&magic.to_le_bytes());
        h.extend_from_slice(&2u16.to_le_bytes());
        h.extend_from_slice(&4u16.to_le_bytes());
        h.extend_from_slice(&[0; 8]);
        h.extend_from_slice(&SNAPLEN.to_le_bytes());
        h.extend_from_slice(&LINKTYPE_ETHERNET.to_le_bytes());
        w.write_all(&h)?;
        Ok(Self { w, res })
    }

    /// Alttaki yazıcıyı geri verir.
    pub fn into_inner(self) -> W {
        self.w
    }
}

impl<W: Write> CaptureWriter for PcapWriter<W> {
    fn write_packet(&mut self, pkt: &RawPacket) -> Result<()> {
        let (cap, orig) = lens(pkt)?;
        let d = since_epoch(pkt);
        let secs = u32::try_from(d.as_secs()).unwrap_or(u32::MAX);
        let frac = match self.res {
            TsResolution::Micro => d.subsec_micros(),
            TsResolution::Nano => d.subsec_nanos(),
        };
        let mut h = [0u8; 16];
        h[0..4].copy_from_slice(&secs.to_le_bytes());
        h[4..8].copy_from_slice(&frac.to_le_bytes());
        h[8..12].copy_from_slice(&cap.to_le_bytes());
        h[12..16].copy_from_slice(&orig.to_le_bytes());
        self.w.write_all(&h)?;
        self.w.write_all(&pkt.data)?;
        Ok(())
    }

    fn flush(&mut self) -> Result<()> {
        Ok(self.w.flush()?)
    }
}

/// pcapng yazıcı: SHB + tek Ethernet IDB + EPB'ler (little-endian).
pub struct PcapngWriter<W: Write> {
    w: W,
    res: TsResolution,
}

impl<W: Write> PcapngWriter<W> {
    /// `if_tsresol=9` (nanosaniye) ile başlıkları yazar.
    ///
    /// # Errors
    /// G/Ç hatası.
    pub fn new(w: W) -> Result<Self> {
        Self::with_resolution(w, TsResolution::Nano)
    }

    /// Belirtilen çözünürlükle (`if_tsresol` 6 ya da 9) başlıkları yazar.
    ///
    /// # Errors
    /// G/Ç hatası.
    pub fn with_resolution(mut w: W, res: TsResolution) -> Result<Self> {
        let mut b = Vec::with_capacity(60);
        // SHB
        b.extend_from_slice(&0x0A0D_0D0Au32.to_le_bytes());
        b.extend_from_slice(&28u32.to_le_bytes());
        b.extend_from_slice(&0x1A2B_3C4Du32.to_le_bytes());
        b.extend_from_slice(&1u16.to_le_bytes());
        b.extend_from_slice(&0u16.to_le_bytes());
        b.extend_from_slice(&(-1i64).to_le_bytes());
        b.extend_from_slice(&28u32.to_le_bytes());
        // IDB
        let tsresol: u8 = match res {
            TsResolution::Micro => 6,
            TsResolution::Nano => 9,
        };
        b.extend_from_slice(&1u32.to_le_bytes());
        b.extend_from_slice(&32u32.to_le_bytes());
        b.extend_from_slice(&1u16.to_le_bytes());
        b.extend_from_slice(&0u16.to_le_bytes());
        b.extend_from_slice(&SNAPLEN.to_le_bytes());
        b.extend_from_slice(&9u16.to_le_bytes());
        b.extend_from_slice(&1u16.to_le_bytes());
        b.extend_from_slice(&[tsresol, 0, 0, 0]);
        b.extend_from_slice(&[0; 4]);
        b.extend_from_slice(&32u32.to_le_bytes());
        w.write_all(&b)?;
        Ok(Self { w, res })
    }

    /// Alttaki yazıcıyı geri verir.
    pub fn into_inner(self) -> W {
        self.w
    }
}

impl<W: Write> CaptureWriter for PcapngWriter<W> {
    fn write_packet(&mut self, pkt: &RawPacket) -> Result<()> {
        let (cap, orig) = lens(pkt)?;
        let d = since_epoch(pkt);
        let units = match self.res {
            TsResolution::Micro => d.as_micros(),
            TsResolution::Nano => d.as_nanos(),
        };
        let units = u64::try_from(units).unwrap_or(u64::MAX);
        let pad = (4 - pkt.data.len() % 4) % 4;
        let total = u32::try_from(32 + pkt.data.len() + pad)
            .map_err(|_| Error::TooLarge(pkt.data.len()))?;
        let mut h = Vec::with_capacity(28);
        h.extend_from_slice(&6u32.to_le_bytes());
        h.extend_from_slice(&total.to_le_bytes());
        h.extend_from_slice(&0u32.to_le_bytes());
        // Üst/alt 32 bit; kesme kasıtlı.
        h.extend_from_slice(&((units >> 32) as u32).to_le_bytes());
        h.extend_from_slice(&((units & 0xFFFF_FFFF) as u32).to_le_bytes());
        h.extend_from_slice(&cap.to_le_bytes());
        h.extend_from_slice(&orig.to_le_bytes());
        self.w.write_all(&h)?;
        self.w.write_all(&pkt.data)?;
        self.w.write_all(&[0u8; 3][..pad])?;
        self.w.write_all(&total.to_le_bytes())?;
        Ok(())
    }

    fn flush(&mut self) -> Result<()> {
        Ok(self.w.flush()?)
    }
}
