//! Test/bench yardımcısı: elle Ethernet/IPv{4,6}/TCP|UDP çerçeveleri üretir ve
//! `pakiz_dissect::Registry` ile ayrıştırır. Checksum'lar sıfırdır.

#![allow(dead_code, clippy::unwrap_used)]

use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, SystemTime};

use pakiz_dissect::{Dissection, RawPacket, Registry};
use pakiz_flow::{FlowTable, PacketAnalysis};

pub const FIN: u16 = 0x01;
pub const SYN: u16 = 0x02;
pub const RST: u16 = 0x04;
pub const PSH: u16 = 0x08;
pub const ACK: u16 = 0x10;

#[derive(Clone, Debug)]
pub struct Tcp {
    pub seq: u32,
    pub ack: u32,
    pub flags: u16,
    pub win: u16,
    pub wscale: Option<u8>,
    pub payload: Vec<u8>,
}

impl Tcp {
    pub fn new(seq: u32, ack: u32, flags: u16, payload: &[u8]) -> Self {
        Self {
            seq,
            ack,
            flags,
            win: 1000,
            wscale: None,
            payload: payload.to_vec(),
        }
    }
    pub fn win(mut self, w: u16) -> Self {
        self.win = w;
        self
    }
    pub fn ws(mut self, s: u8) -> Self {
        self.wscale = Some(s);
        self
    }
}

fn eth(ethertype: u16, l3: &[u8]) -> Vec<u8> {
    let mut f = vec![0x02, 0, 0, 0, 0, 2, 0x02, 0, 0, 0, 0, 1];
    f.extend_from_slice(&ethertype.to_be_bytes());
    f.extend_from_slice(l3);
    f
}

fn ip(src: IpAddr, dst: IpAddr, proto: u8, l4: &[u8]) -> Vec<u8> {
    match (src, dst) {
        (IpAddr::V4(s), IpAddr::V4(d)) => {
            let total = u16::try_from(20 + l4.len()).unwrap();
            let mut h = vec![0x45, 0];
            h.extend_from_slice(&total.to_be_bytes());
            h.extend_from_slice(&[0, 1, 0x40, 0, 64, proto, 0, 0]);
            h.extend_from_slice(&s.octets());
            h.extend_from_slice(&d.octets());
            h.extend_from_slice(l4);
            eth(0x0800, &h)
        }
        (IpAddr::V6(s), IpAddr::V6(d)) => {
            let plen = u16::try_from(l4.len()).unwrap();
            let mut h = vec![0x60, 0, 0, 0];
            h.extend_from_slice(&plen.to_be_bytes());
            h.extend_from_slice(&[proto, 64]);
            h.extend_from_slice(&s.octets());
            h.extend_from_slice(&d.octets());
            h.extend_from_slice(l4);
            eth(0x86dd, &h)
        }
        _ => panic!("karışık IP sürümü"),
    }
}

pub fn tcp_frame(src: SocketAddr, dst: SocketAddr, t: &Tcp) -> Vec<u8> {
    let opts: Vec<u8> = t.wscale.map_or(vec![], |s| vec![1, 3, 3, s]);
    let hl = 20 + opts.len();
    let mut h = Vec::new();
    h.extend_from_slice(&src.port().to_be_bytes());
    h.extend_from_slice(&dst.port().to_be_bytes());
    h.extend_from_slice(&t.seq.to_be_bytes());
    h.extend_from_slice(&t.ack.to_be_bytes());
    let off_flags = (u16::try_from(hl / 4).unwrap() << 12) | t.flags;
    h.extend_from_slice(&off_flags.to_be_bytes());
    h.extend_from_slice(&t.win.to_be_bytes());
    h.extend_from_slice(&[0, 0, 0, 0]);
    h.extend_from_slice(&opts);
    h.extend_from_slice(&t.payload);
    ip(src.ip(), dst.ip(), 6, &h)
}

pub fn udp_frame(src: SocketAddr, dst: SocketAddr, payload: &[u8]) -> Vec<u8> {
    let mut h = Vec::new();
    h.extend_from_slice(&src.port().to_be_bytes());
    h.extend_from_slice(&dst.port().to_be_bytes());
    h.extend_from_slice(&u16::try_from(8 + payload.len()).unwrap().to_be_bytes());
    h.extend_from_slice(&[0, 0]);
    h.extend_from_slice(payload);
    ip(src.ip(), dst.ip(), 17, &h)
}

pub fn raw(data: Vec<u8>, ts_ms: u64) -> RawPacket {
    RawPacket {
        ts: SystemTime::UNIX_EPOCH + Duration::from_millis(ts_ms),
        orig_len: u32::try_from(data.len()).unwrap(),
        data,
        ifindex: 1,
    }
}

/// Sanal yakalama: paket numarası ve zamanı otomatik ilerler (varsayılan 10 ms).
pub struct Cap {
    pub reg: Registry,
    pub table: FlowTable,
    pub no: u64,
    pub ts_ms: u64,
    pub step_ms: u64,
}

impl Cap {
    pub fn new() -> Self {
        Self::with(FlowTable::new())
    }
    pub fn with(table: FlowTable) -> Self {
        Self {
            reg: Registry::default(),
            table,
            no: 0,
            ts_ms: 0,
            step_ms: 10,
        }
    }
    pub fn frame(&mut self, data: Vec<u8>) -> Option<PacketAnalysis> {
        self.no += 1;
        self.ts_ms += self.step_ms;
        let p = raw(data, self.ts_ms);
        let d: Dissection = self.reg.dissect(&p);
        self.table.process(self.no, &p, &d)
    }
    pub fn tcp(&mut self, src: SocketAddr, dst: SocketAddr, t: &Tcp) -> PacketAnalysis {
        self.frame(tcp_frame(src, dst, t)).unwrap()
    }
    pub fn udp(&mut self, src: SocketAddr, dst: SocketAddr, p: &[u8]) -> PacketAnalysis {
        self.frame(udp_frame(src, dst, p)).unwrap()
    }
}

pub fn sa(s: &str) -> SocketAddr {
    s.parse().unwrap()
}

/// xorshift64* — testler için küçük deterministik PRNG.
pub struct Rng(pub u64);

impl Rng {
    pub fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }
    pub fn below(&mut self, n: usize) -> usize {
        usize::try_from(self.next() % u64::try_from(n).unwrap()).unwrap()
    }
    pub fn shuffle<T>(&mut self, v: &mut [T]) {
        for i in (1..v.len()).rev() {
            let j = self.below(i + 1);
            v.swap(i, j);
        }
    }
}
