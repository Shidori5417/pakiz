use std::fs::File;
use std::io::{BufReader, ErrorKind, Read};
use std::ops::Range;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use pakiz_dissect::RawPacket;

use crate::{Error, Format, Result};

/// Desteklenen tek bağlantı katmanı tipi.
pub const LINKTYPE_ETHERNET: u32 = 1;
/// Tek paket/blok için üst sınır (bozuk uzunlukla dev ayırmayı önler).
const MAX_LEN: u32 = 64 << 20;
const SHB: u32 = 0x0A0D_0D0A;
const BOM: u32 = 0x1A2B_3C4D;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Endian {
    Little,
    Big,
}

impl Endian {
    fn u16(self, b: [u8; 2]) -> u16 {
        match self {
            Self::Little => u16::from_le_bytes(b),
            Self::Big => u16::from_be_bytes(b),
        }
    }
    fn u32(self, b: [u8; 4]) -> u32 {
        match self {
            Self::Little => u32::from_le_bytes(b),
            Self::Big => u32::from_be_bytes(b),
        }
    }
}

fn malformed(offset: u64, msg: impl Into<String>) -> Error {
    Error::Malformed {
        offset,
        msg: msg.into(),
    }
}

fn arr<const N: usize>(b: &[u8], off: usize, at: u64) -> Result<[u8; N]> {
    off.checked_add(N)
        .and_then(|end| b.get(off..end))
        .and_then(|s| s.try_into().ok())
        .ok_or_else(|| malformed(at, "blok gövdesi beklenenden kısa"))
}

/// Konumu sayan okuyucu.
struct Src<R> {
    r: R,
    pos: u64,
}

impl<R: Read> Src<R> {
    /// `Ok(false)`: hiç bayt yok (temiz EOF). Kısmi okuma → `Truncated`.
    fn fill(&mut self, buf: &mut [u8], what: &'static str) -> Result<bool> {
        let mut n = 0;
        while n < buf.len() {
            match self.r.read(&mut buf[n..]) {
                Ok(0) => break,
                Ok(k) => n += k,
                Err(e) if e.kind() == ErrorKind::Interrupted => {}
                Err(e) => return Err(e.into()),
            }
        }
        self.pos += n as u64;
        if n == buf.len() {
            Ok(true)
        } else if n == 0 {
            Ok(false)
        } else {
            Err(Error::Truncated(what))
        }
    }

    fn exact(&mut self, buf: &mut [u8], what: &'static str) -> Result<()> {
        if self.fill(buf, what)? {
            Ok(())
        } else {
            Err(Error::Truncated(what))
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct Iface {
    linktype: u32,
    snaplen: u32,
    tsresol: u8,
}

enum Kind {
    Pcap { endian: Endian, nano: bool },
    Pcapng { endian: Endian, ifaces: Vec<Iface> },
}

/// Bir kaydın verisi okunmadan bilinen bilgileri.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Meta {
    pub offset: u64,
    pub cap_len: u32,
    pub orig_len: u32,
    pub ts: SystemTime,
    pub ifindex: u32,
}

/// pcap / pcapng okuyucu; biçim magic'ten otomatik algılanır.
pub struct CaptureReader<R = BufReader<File>> {
    src: Src<R>,
    kind: Kind,
    buf: Vec<u8>,
    data: Range<usize>,
}

impl CaptureReader {
    /// Dosyayı açar ve başlığı doğrular.
    ///
    /// # Errors
    /// G/Ç hatası, bilinmeyen magic, desteklenmeyen linktype ya da bozuk başlık.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        Self::from_reader(BufReader::new(File::open(path)?))
    }
}

impl<R: Read> CaptureReader<R> {
    /// Herhangi bir `Read` kaynağından okuyucu kurar.
    ///
    /// # Errors
    /// Bkz. [`CaptureReader::open`].
    pub fn from_reader(r: R) -> Result<Self> {
        let mut src = Src { r, pos: 0 };
        let mut m = [0u8; 4];
        src.exact(&mut m, "dosya başlığı")?;
        let (endian, nano) = match u32::from_le_bytes(m) {
            0xa1b2_c3d4 => (Endian::Little, false),
            0xd4c3_b2a1 => (Endian::Big, false),
            0xa1b2_3c4d => (Endian::Little, true),
            0x4d3c_b2a1 => (Endian::Big, true),
            SHB => {
                let endian = read_shb_rest(&mut src, 0)?;
                return Ok(Self {
                    src,
                    kind: Kind::Pcapng {
                        endian,
                        ifaces: Vec::new(),
                    },
                    buf: Vec::new(),
                    data: 0..0,
                });
            }
            _ => return Err(Error::UnknownMagic(u32::from_be_bytes(m))),
        };
        let mut h = [0u8; 20];
        src.exact(&mut h, "pcap global başlığı")?;
        let linktype = endian.u32(arr(&h, 16, 0)?) & 0xFFFF;
        if linktype != LINKTYPE_ETHERNET {
            return Err(Error::UnsupportedLinkType(linktype));
        }
        Ok(Self {
            src,
            kind: Kind::Pcap { endian, nano },
            buf: Vec::new(),
            data: 0..0,
        })
    }

    /// Dosya biçimi.
    #[must_use]
    pub fn format(&self) -> Format {
        match self.kind {
            Kind::Pcap { .. } => Format::Pcap,
            Kind::Pcapng { .. } => Format::Pcapng,
        }
    }

    /// Şimdiye kadar okunan bayt sayısı (ilerleme raporu için).
    #[must_use]
    pub fn position(&self) -> u64 {
        self.src.pos
    }

    /// Sıradaki paket; dosya sonunda `Ok(None)`.
    ///
    /// # Errors
    /// Kesik/bozuk kayıt, desteklenmeyen linktype veya G/Ç hatası.
    pub fn next_packet(&mut self) -> Result<Option<RawPacket>> {
        Ok(self.next_record()?.map(|m| RawPacket {
            ts: m.ts,
            data: self.buf[self.data.clone()].to_vec(),
            orig_len: m.orig_len,
            ifindex: m.ifindex,
        }))
    }

    pub(crate) fn next_record(&mut self) -> Result<Option<Meta>> {
        match &mut self.kind {
            Kind::Pcap { endian, nano } => {
                let (endian, nano) = (*endian, *nano);
                let start = self.src.pos;
                let mut h = [0u8; 16];
                if !self.src.fill(&mut h, "paket kaydı başlığı")? {
                    return Ok(None);
                }
                let secs = endian.u32(arr(&h, 0, start)?);
                let frac = endian.u32(arr(&h, 4, start)?);
                let cap_len = endian.u32(arr(&h, 8, start)?);
                let orig_len = endian.u32(arr(&h, 12, start)?);
                if cap_len > MAX_LEN {
                    return Err(malformed(
                        start,
                        format!("kayıt uzunluğu {cap_len} çok büyük"),
                    ));
                }
                self.buf.resize(cap_len as usize, 0);
                self.src.exact(&mut self.buf, "paket verisi")?;
                self.data = 0..self.buf.len();
                let frac_ns = if nano {
                    u64::from(frac)
                } else {
                    u64::from(frac) * 1000
                };
                let ts = UNIX_EPOCH
                    + Duration::from_secs(u64::from(secs))
                    + Duration::from_nanos(frac_ns);
                Ok(Some(Meta {
                    offset: start + 16,
                    cap_len,
                    orig_len,
                    ts,
                    ifindex: 0,
                }))
            }
            Kind::Pcapng { endian, ifaces } => loop {
                let start = self.src.pos;
                let mut t = [0u8; 4];
                if !self.src.fill(&mut t, "pcapng blok başlığı")? {
                    return Ok(None);
                }
                let btype = endian.u32(t);
                if btype == SHB {
                    *endian = read_shb_rest(&mut self.src, start)?;
                    ifaces.clear();
                    continue;
                }
                let mut l = [0u8; 4];
                self.src.exact(&mut l, "pcapng blok uzunluğu")?;
                let len = endian.u32(l);
                if len < 12 || len % 4 != 0 || len > MAX_LEN {
                    return Err(malformed(start, format!("geçersiz blok uzunluğu {len}")));
                }
                let body = (len - 12) as usize;
                self.buf.resize(body + 4, 0);
                self.src.exact(&mut self.buf, "pcapng blok gövdesi")?;
                if endian.u32(arr(&self.buf, body, start)?) != len {
                    return Err(malformed(start, "blok sonu uzunluğu başlıkla uyuşmuyor"));
                }
                if let Some((meta, data)) =
                    packet_block(*endian, btype, &self.buf[..body], ifaces, start)?
                {
                    self.data = data;
                    return Ok(Some(meta));
                }
            },
        }
    }
}

/// EPB / OPB / SPB çözümü; diğer bloklar (IDB hariç) atlanır → `None`.
fn packet_block(
    e: Endian,
    btype: u32,
    b: &[u8],
    ifaces: &mut Vec<Iface>,
    start: u64,
) -> Result<Option<(Meta, Range<usize>)>> {
    let body = b.len();
    match btype {
        1 => ifaces.push(parse_idb(e, b, start)?),
        2 | 6 => {
            let id = if btype == 6 {
                e.u32(arr(b, 0, start)?)
            } else {
                u32::from(e.u16(arr(b, 0, start)?))
            };
            let hi = e.u32(arr(b, 4, start)?);
            let lo = e.u32(arr(b, 8, start)?);
            let cap_len = e.u32(arr(b, 12, start)?);
            let orig_len = e.u32(arr(b, 16, start)?);
            let iface = iface(ifaces, id)?;
            let end = 20 + cap_len as usize;
            if end > body {
                return Err(malformed(start, "paket verisi blok sınırını aşıyor"));
            }
            let units = (u64::from(hi) << 32) | u64::from(lo);
            let ts = ts_from_units(units, iface.tsresol, start)?;
            let meta = Meta {
                offset: start + 28,
                cap_len,
                orig_len,
                ts,
                ifindex: id,
            };
            return Ok(Some((meta, 20..end)));
        }
        3 => {
            let orig_len = e.u32(arr(b, 0, start)?);
            let iface = iface(ifaces, 0)?;
            let room = u32::try_from(body - 4).unwrap_or(u32::MAX);
            let mut cap_len = orig_len.min(room);
            if iface.snaplen != 0 {
                cap_len = cap_len.min(iface.snaplen);
            }
            let meta = Meta {
                offset: start + 12,
                cap_len,
                orig_len,
                ts: UNIX_EPOCH,
                ifindex: 0,
            };
            return Ok(Some((meta, 4..4 + cap_len as usize)));
        }
        _ => {}
    }
    Ok(None)
}

fn iface(ifaces: &[Iface], id: u32) -> Result<Iface> {
    let i = *ifaces.get(id as usize).ok_or(Error::UnknownInterface(id))?;
    if i.linktype != LINKTYPE_ETHERNET {
        return Err(Error::UnsupportedLinkType(i.linktype));
    }
    Ok(i)
}

/// SHB'nin tip alanından sonrasını okur; bölümün bayt sırasını döner.
fn read_shb_rest<R: Read>(src: &mut Src<R>, start: u64) -> Result<Endian> {
    let mut h = [0u8; 8];
    src.exact(&mut h, "pcapng bölüm başlığı")?;
    let bom = arr::<4>(&h, 4, start)?;
    let endian = if u32::from_le_bytes(bom) == BOM {
        Endian::Little
    } else if u32::from_be_bytes(bom) == BOM {
        Endian::Big
    } else {
        return Err(malformed(start, "SHB bayt sırası işareti geçersiz"));
    };
    let len = endian.u32(arr(&h, 0, start)?);
    if len < 28 || len % 4 != 0 || len > MAX_LEN {
        return Err(malformed(start, format!("geçersiz SHB uzunluğu {len}")));
    }
    let mut rest = vec![0u8; (len - 12) as usize];
    src.exact(&mut rest, "pcapng bölüm başlığı")?;
    if endian.u32(arr(&rest, rest.len() - 4, start)?) != len {
        return Err(malformed(start, "SHB sonu uzunluğu uyuşmuyor"));
    }
    Ok(endian)
}

fn parse_idb(e: Endian, b: &[u8], start: u64) -> Result<Iface> {
    let linktype = u32::from(e.u16(arr(b, 0, start)?));
    let snaplen = e.u32(arr(b, 4, start)?);
    let mut tsresol = 6;
    let mut off = 8;
    while off + 4 <= b.len() {
        let code = e.u16(arr(b, off, start)?);
        let olen = usize::from(e.u16(arr(b, off + 2, start)?));
        if code == 0 {
            break;
        }
        let val = off + 4;
        if val + olen > b.len() {
            return Err(malformed(start, "IDB seçeneği blok sınırını aşıyor"));
        }
        if code == 9 && olen >= 1 {
            tsresol = b[val];
            let v = tsresol & 0x7f;
            if (tsresol & 0x80 == 0 && v > 19) || v > 63 {
                return Err(malformed(start, format!("geçersiz if_tsresol {tsresol}")));
            }
        }
        off = val + olen.div_ceil(4) * 4;
    }
    Ok(Iface {
        linktype,
        snaplen,
        tsresol,
    })
}

fn ts_from_units(units: u64, resol: u8, at: u64) -> Result<SystemTime> {
    let v = u32::from(resol & 0x7f);
    let (secs, nanos) = if resol & 0x80 == 0 {
        let div = 10u64.pow(v);
        let rem = units % div;
        let nanos = if v <= 9 {
            rem * 10u64.pow(9 - v)
        } else {
            rem / 10u64.pow(v - 9)
        };
        (units / div, nanos)
    } else {
        let rem = if v == 0 { 0 } else { units & ((1u64 << v) - 1) };
        let nanos = (u128::from(rem) * 1_000_000_000) >> v;
        (units >> v, u64::try_from(nanos).unwrap_or(0))
    };
    UNIX_EPOCH
        .checked_add(Duration::from_secs(secs) + Duration::from_nanos(nanos))
        .ok_or_else(|| malformed(at, "zaman damgası aralık dışı"))
}
