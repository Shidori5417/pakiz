#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::Cursor;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use pakiz_dissect::RawPacket;
use pakiz_storage::{
    create, CaptureReader, CaptureWriter, Error, Format, IndexedFile, PcapWriter, PcapngWriter,
    TsResolution,
};

fn hex(s: &str) -> Vec<u8> {
    let s: String = s.split_whitespace().collect();
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn read_all(bytes: &[u8]) -> Result<Vec<RawPacket>, Error> {
    let mut r = CaptureReader::from_reader(Cursor::new(bytes))?;
    let mut v = Vec::new();
    while let Some(p) = r.next_packet()? {
        v.push(p);
    }
    Ok(v)
}

fn at(secs: u64, nanos: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(secs) + Duration::from_nanos(nanos)
}

struct Tmp(PathBuf);
impl Tmp {
    fn new(ext: &str) -> Self {
        static N: AtomicU32 = AtomicU32::new(0);
        let n = N.fetch_add(1, Ordering::Relaxed);
        Self(std::env::temp_dir().join(format!("pakiz-storage-{}-{n}.{ext}", std::process::id())))
    }
}
impl Drop for Tmp {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

const PCAP_LE: &str = "d4c3b2a1 0200 0400 00000000 00000000 ffff0000 01000000
    64000000 f4010000 04000000 3c000000 deadbeef
    65000000 00000000 02000000 02000000 cafe";

const PCAP_BE_NANO: &str = "a1b23c4d 0002 0004 00000000 00000000 0000ffff 00000001
    00000064 000001f4 00000003 00000003 010203";

// SHB + IDB0(tsresol=9) + EPB(if0) + bilinmeyen blok + IDB1(varsayılan µs) + EPB(if1) + SPB
const PCAPNG: &str = "
    0a0d0d0a 1c000000 4d3c2b1a 0100 0000 ffffffffffffffff 1c000000
    01000000 20000000 0100 0000 00000400 0900 0100 09000000 0000 0000 20000000
    06000000 24000000 00000000 00000000 002f6859 04000000 04000000 deadbeef 24000000
    ad0b0000 10000000 11223344 10000000
    01000000 14000000 0100 0000 00000000 14000000
    06000000 24000000 01000000 00000000 40420f00 03000000 05000000 aabbcc00 24000000
    03000000 14000000 02000000 1234 0000 14000000";

#[test]
fn pcap_little_endian_micro() {
    let p = read_all(&hex(PCAP_LE)).unwrap();
    assert_eq!(p.len(), 2);
    assert_eq!(p[0].data, hex("deadbeef"));
    assert_eq!(p[0].orig_len, 60);
    assert_eq!(p[0].ts, at(100, 500_000));
    assert_eq!(p[1].ts, at(101, 0));
    assert_eq!(p[1].data, hex("cafe"));
}

#[test]
fn pcap_big_endian_nano() {
    let r = CaptureReader::from_reader(Cursor::new(hex(PCAP_BE_NANO))).unwrap();
    assert_eq!(r.format(), Format::Pcap);
    let p = read_all(&hex(PCAP_BE_NANO)).unwrap();
    assert_eq!(p.len(), 1);
    assert_eq!(p[0].ts, at(100, 500));
    assert_eq!(p[0].data, vec![1, 2, 3]);
}

#[test]
fn pcap_unsupported_linktype() {
    let mut b = hex(PCAP_LE);
    b[20] = 113; // LINKTYPE_LINUX_SLL
    assert!(matches!(read_all(&b), Err(Error::UnsupportedLinkType(113))));
}

#[test]
fn unknown_magic() {
    assert!(matches!(
        read_all(&hex("00112233 00000000")),
        Err(Error::UnknownMagic(0x0011_2233))
    ));
}

#[test]
fn pcapng_handmade() {
    let p = read_all(&hex(PCAPNG)).unwrap();
    assert_eq!(p.len(), 3);
    assert_eq!(p[0].ifindex, 0);
    assert_eq!(p[0].ts, at(1, 500_000_000));
    assert_eq!(p[0].data, hex("deadbeef"));
    assert_eq!(p[1].ifindex, 1);
    assert_eq!(p[1].ts, at(1, 0)); // 1_000_000 µs
    assert_eq!(p[1].data, hex("aabbcc"));
    assert_eq!(p[1].orig_len, 5);
    assert_eq!(p[2].data, hex("1234")); // SPB
    assert_eq!(p[2].orig_len, 2);
}

#[test]
fn pcapng_unknown_interface_and_bad_block() {
    let mut b = hex(PCAPNG);
    b[28 + 32 + 8] = 7; // ilk EPB arayüz id'si
    assert!(matches!(read_all(&b), Err(Error::UnknownInterface(7))));
    let mut b = hex(PCAPNG);
    b[28 + 4] = 0x21; // IDB uzunluğu 4'ün katı değil
    assert!(matches!(read_all(&b), Err(Error::Malformed { .. })));
}

#[test]
fn truncated_prefixes_never_panic() {
    for src in [PCAP_LE, PCAP_BE_NANO, PCAPNG] {
        let full = hex(src);
        let n = read_all(&full).unwrap().len();
        for len in 0..full.len() {
            match read_all(&full[..len]) {
                Ok(v) => assert!(v.len() < n, "len {len}"),
                Err(Error::Truncated(_)) => {}
                Err(e) => panic!("beklenmeyen hata {e} (len {len})"),
            }
        }
    }
}

fn sample() -> Vec<RawPacket> {
    (0..50u32)
        .map(|i| RawPacket {
            ts: at(1_700_000_000 + u64::from(i), u64::from(i) * 1_234_567),
            data: (0..(i % 7 + 1) * 9)
                .map(|b| u8::try_from((b ^ i) & 0xff).unwrap())
                .collect(),
            orig_len: (i % 7 + 1) * 9 + i % 3,
            ifindex: 0,
        })
        .collect()
}

fn truncate_us(t: SystemTime) -> SystemTime {
    let d = t.duration_since(UNIX_EPOCH).unwrap();
    UNIX_EPOCH + Duration::from_micros(u64::try_from(d.as_micros()).unwrap())
}

#[test]
fn roundtrip_all_formats_and_resolutions() {
    for fmt in [Format::Pcap, Format::Pcapng] {
        for res in [TsResolution::Micro, TsResolution::Nano] {
            let mut w: Box<dyn CaptureWriter> = match fmt {
                Format::Pcap => Box::new(PcapWriter::with_resolution(Vec::new(), res).unwrap()),
                Format::Pcapng => Box::new(PcapngWriter::with_resolution(Vec::new(), res).unwrap()),
            };
            let pkts = sample();
            for p in &pkts {
                w.write_packet(p).unwrap();
            }
            w.flush().unwrap();
            drop(w);
            // Box<dyn> içinden baytları almak için yeniden somut tiple yaz.
            let bytes = match fmt {
                Format::Pcap => {
                    let mut w = PcapWriter::with_resolution(Vec::new(), res).unwrap();
                    for p in &pkts {
                        w.write_packet(p).unwrap();
                    }
                    w.into_inner()
                }
                Format::Pcapng => {
                    let mut w = PcapngWriter::with_resolution(Vec::new(), res).unwrap();
                    for p in &pkts {
                        w.write_packet(p).unwrap();
                    }
                    w.into_inner()
                }
            };
            let r = CaptureReader::from_reader(Cursor::new(&bytes)).unwrap();
            assert_eq!(r.format(), fmt);
            let got = read_all(&bytes).unwrap();
            assert_eq!(got.len(), pkts.len());
            for (g, p) in got.iter().zip(&pkts) {
                let want_ts = match res {
                    TsResolution::Micro => truncate_us(p.ts),
                    TsResolution::Nano => p.ts,
                };
                assert_eq!(g.ts, want_ts, "{fmt:?} {res:?}");
                assert_eq!(g.data, p.data);
                assert_eq!(g.orig_len, p.orig_len);
                assert_eq!(g.ifindex, 0);
            }
        }
    }
}

#[test]
fn create_from_extension_and_indexed_random_access() {
    assert_eq!(Format::from_path("a/b.PCAPNG"), Format::Pcapng);
    assert_eq!(Format::from_path("a/b.cap"), Format::Pcap);
    assert_eq!(Format::from_path("noext"), Format::Pcap);
    let pkts = sample();
    for ext in ["pcap", "pcapng"] {
        let tmp = Tmp::new(ext);
        let mut w = create(&tmp.0, Format::from_path(&tmp.0)).unwrap();
        for p in &pkts {
            w.write_packet(p).unwrap();
        }
        w.flush().unwrap();
        drop(w);

        let r = CaptureReader::open(&tmp.0).unwrap();
        assert_eq!(r.format(), Format::from_path(&tmp.0));

        let mut idx = IndexedFile::open(&tmp.0).unwrap();
        assert!(idx.is_empty());
        assert_eq!(idx.index_more(10).unwrap(), 10);
        assert!(!idx.is_complete());
        assert!(idx.bytes_scanned() < idx.file_len());
        let mut calls = 0;
        idx.index_all(|done, total| {
            calls += 1;
            assert!(done <= total);
        })
        .unwrap();
        assert!(calls >= 1);
        assert!(idx.is_complete());
        assert_eq!(idx.len(), pkts.len());
        for i in [49usize, 0, 17, 3, 33, 17, 48] {
            assert_eq!(idx.get(i).unwrap(), pkts[i]);
        }
        assert!(matches!(
            idx.get(50),
            Err(Error::OutOfRange { index: 50, len: 50 })
        ));
    }
}

#[test]
fn indexed_truncated_file_keeps_partial() {
    let pkts = sample();
    let mut w = PcapWriter::new(Vec::new()).unwrap();
    for p in &pkts {
        w.write_packet(p).unwrap();
    }
    let mut bytes = w.into_inner();
    bytes.truncate(bytes.len() - 5);
    let tmp = Tmp::new("pcap");
    std::fs::write(&tmp.0, &bytes).unwrap();
    let mut idx = IndexedFile::open(&tmp.0).unwrap();
    assert!(matches!(idx.index_all(|_, _| {}), Err(Error::Truncated(_))));
    assert!(idx.is_complete());
    assert_eq!(idx.len(), pkts.len() - 1);
    assert_eq!(idx.get(48).unwrap(), pkts[48]);
}

#[test]
fn indexed_large_file_incremental() {
    const N: u32 = 200_000;
    let tmp = Tmp::new("pcap");
    let mut w = create(&tmp.0, Format::Pcap).unwrap();
    for i in 0..N {
        let mut data = vec![0u8; 60];
        data[..4].copy_from_slice(&i.to_be_bytes());
        w.write_packet(&RawPacket {
            ts: at(1_700_000_000, u64::from(i) * 1000),
            orig_len: 60,
            data,
            ifindex: 0,
        })
        .unwrap();
    }
    w.flush().unwrap();
    drop(w);
    let mut f = IndexedFile::open(&tmp.0).unwrap();
    let mut steps = 0;
    while f.index_more(10_000).unwrap() > 0 {
        steps += 1;
        assert!(f.bytes_scanned() <= f.file_len());
    }
    assert!(f.is_complete());
    assert_eq!(steps, 20);
    assert_eq!(f.len(), N as usize);
    for i in [0u32, 1, 99_999, N - 1] {
        assert_eq!(f.get(i as usize).unwrap().data[..4], i.to_be_bytes());
    }
}
