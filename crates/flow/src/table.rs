//! Akış tablosu, TCP analizi ve konuşma özetleri.

use std::collections::{BTreeMap, HashMap};
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, SystemTime};

use pakiz_dissect::{Dissection, FieldValue, Layer, RawPacket};

use crate::reassembly::{Delivery, Reassembler};
use crate::stream::{Stream, StreamId};
use crate::{Dir, FlowError, FlowKey, KeyDir, Proto};

const FIN: u16 = 0x01;
const SYN: u16 = 0x02;
const RST: u16 = 0x04;
const ACK: u16 = 0x10;

/// Tablo ayarları.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    /// En fazla eşzamanlı akış; aşılınca en uzun süredir dokunulmayan atılır (LRU).
    pub max_flows: usize,
    /// Bu süre paket görmeyen akış atılır (paket zaman damgalarına göre).
    pub idle_timeout: Option<Duration>,
    /// Yön başına bellekte tutulan en fazla birleşik veri.
    pub max_buffer: usize,
    /// Boşluğun ötesinde bu kadar bayt beklerse boşluk kayıp sayılır.
    pub gap_threshold: usize,
    /// Boşluk dolduran segment, yöndeki en yüksek segmentten bu süre içinde
    /// gelirse Out-Of-Order, sonra gelirse Retransmission sayılır.
    pub ooo_threshold: Duration,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            max_flows: 100_000,
            idle_timeout: Some(Duration::from_secs(600)),
            max_buffer: 4 << 20,
            gap_threshold: 256 << 10,
            ooo_threshold: Duration::from_millis(3),
        }
    }
}

/// TCP analiz bayrakları (Wireshark `tcp.analysis.*` karşılıkları).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TcpAnalysis {
    Retransmission,
    FastRetransmission,
    SpuriousRetransmission,
    OutOfOrder,
    /// Kaçıncı tekrar ACK olduğu (1'den başlar).
    DuplicateAck(u32),
    ZeroWindow,
    ZeroWindowProbe,
    WindowFull,
    Rst,
    KeepAlive,
    PreviousSegmentNotCaptured,
    AckedUnseenSegment,
}

/// TCP bağlantı durumu.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TcpState {
    SynSent,
    Established,
    /// Her iki yönden FIN görüldü.
    Closed,
    Reset,
}

/// Paket başına TCP bilgisi.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpInfo {
    /// Göreli sıra no (SYN = 0; SYN görülmediyse ilk segment = 0).
    pub rel_seq: u32,
    /// Göreli ACK (ACK bayrağı yoksa veya karşı yön bilinmiyorsa `None`).
    pub rel_ack: Option<u32>,
    /// Bu segmentten sonraki göreli sıra no (SYN/FIN 1 sayılır).
    pub next_rel_seq: u32,
    /// TCP yük uzunluğu.
    pub len: u32,
    /// Ölçeklenmiş pencere (her iki SYN'de WS varsa uygulanır).
    pub window: u32,
    pub analysis: Vec<TcpAnalysis>,
}

/// `FlowTable::process` sonucu.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PacketAnalysis {
    pub stream: StreamId,
    pub key: FlowKey,
    pub key_dir: KeyDir,
    pub dir: Dir,
    pub tcp: Option<TcpInfo>,
}

/// Konuşma özeti. Dizi indeksleri [`Dir::index`] (0 = istemci→sunucu).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Conversation {
    pub stream: StreamId,
    pub key: FlowKey,
    pub client: SocketAddr,
    pub server: SocketAddr,
    pub packets: [u64; 2],
    /// Çerçeve baytları (kablodaki uzunluk).
    pub bytes: [u64; 2],
    pub first: SystemTime,
    pub last: SystemTime,
    pub duration: Duration,
    /// Yalnızca TCP.
    pub state: Option<TcpState>,
}

#[derive(Debug, Clone, Copy, Default)]
#[allow(clippy::struct_excessive_bools)]
struct TcpDir {
    init: bool,
    syn: bool,
    isn: u32,
    wscale: Option<u8>,
    next_seq: u32,
    max_ts: Option<SystemTime>,
    ack_valid: bool,
    last_ack: u32,
    last_win: u16,
    dup: u32,
    fin: bool,
    ref_seq: u32,
    ref_off: i64,
}

impl TcpDir {
    fn start(seq: u32, syn: bool, wscale: Option<u8>) -> Self {
        let data_base = seq.wrapping_add(u32::from(syn));
        Self {
            init: true,
            syn,
            isn: seq,
            wscale,
            next_seq: seq,
            ref_seq: data_base,
            ..Self::default()
        }
    }

    /// Sıra no → ilk veri baytına göre ofset (sarmalamayı çözer).
    fn offset(&mut self, seq: u32) -> i64 {
        let diff = i64::from(seq.wrapping_sub(self.ref_seq));
        let diff = if diff >= 1 << 31 {
            diff - (1 << 32)
        } else {
            diff
        };
        let off = self.ref_off + diff;
        if diff > 0 {
            self.ref_seq = seq;
            self.ref_off = off;
        }
        off
    }
}

#[derive(Debug, Clone)]
struct TcpFlow {
    dirs: [TcpDir; 2],
    reasm: [Reassembler; 2],
    state: TcpState,
}

#[derive(Debug, Clone)]
struct Flow {
    key: FlowKey,
    client: SocketAddr,
    first: SystemTime,
    last: SystemTime,
    packets: [u64; 2],
    bytes: [u64; 2],
    lru: u64,
    tcp: Option<TcpFlow>,
    stream: Stream,
}

struct Seg<'a> {
    proto: Proto,
    src: SocketAddr,
    dst: SocketAddr,
    payload: &'a [u8],
    tcp: Option<TcpSeg>,
}

#[derive(Clone, Copy)]
struct TcpSeg {
    seq: u32,
    ack: u32,
    flags: u16,
    win: u16,
    len: u32,
    wscale: Option<u8>,
}

/// Wrapping `a < b`.
fn seq_lt(a: u32, b: u32) -> bool {
    a != b && b.wrapping_sub(a) < 1 << 31
}

fn seq_gt(a: u32, b: u32) -> bool {
    seq_lt(b, a)
}

/// TCP/UDP akış tablosu.
#[derive(Debug)]
pub struct FlowTable {
    cfg: Config,
    by_key: HashMap<FlowKey, StreamId>,
    flows: HashMap<StreamId, Flow>,
    lru: BTreeMap<u64, StreamId>,
    tick: u64,
    next_index: [u32; 2],
    evicted: u64,
}

impl Default for FlowTable {
    fn default() -> Self {
        Self::build(Config::default())
    }
}

impl FlowTable {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// # Errors
    /// Sıfır `max_flows`/`max_buffer` veya `gap_threshold > max_buffer`.
    pub fn with_config(cfg: Config) -> Result<Self, FlowError> {
        if cfg.max_flows == 0 {
            return Err(FlowError::InvalidConfig("max_flows 0 olamaz"));
        }
        if cfg.max_buffer == 0 {
            return Err(FlowError::InvalidConfig("max_buffer 0 olamaz"));
        }
        if cfg.gap_threshold > cfg.max_buffer {
            return Err(FlowError::InvalidConfig(
                "gap_threshold max_buffer'dan büyük olamaz",
            ));
        }
        Ok(Self::build(cfg))
    }

    fn build(cfg: Config) -> Self {
        Self {
            cfg,
            by_key: HashMap::new(),
            flows: HashMap::new(),
            lru: BTreeMap::new(),
            tick: 0,
            next_index: [0; 2],
            evicted: 0,
        }
    }

    #[must_use]
    pub fn config(&self) -> &Config {
        &self.cfg
    }

    /// Bellekteki akış sayısı.
    #[must_use]
    pub fn len(&self) -> usize {
        self.flows.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.flows.is_empty()
    }

    /// LRU veya zaman aşımıyla atılan akış sayısı.
    #[must_use]
    pub fn evicted(&self) -> u64 {
        self.evicted
    }

    #[must_use]
    pub fn stream(&self, id: StreamId) -> Option<&Stream> {
        self.flows.get(&id).map(|f| &f.stream)
    }

    /// Tüm akışların özeti (stream id sırasıyla).
    #[must_use]
    pub fn conversations(&self) -> Vec<Conversation> {
        let mut v: Vec<_> = self
            .flows
            .iter()
            .map(|(&id, f)| conversation_of(id, f))
            .collect();
        v.sort_by_key(|c| c.stream);
        v
    }

    /// Tek akışın özeti (bellekte değilse `None`).
    #[must_use]
    pub fn conversation(&self, id: StreamId) -> Option<Conversation> {
        self.flows.get(&id).map(|f| conversation_of(id, f))
    }

    /// Yakalama sonu: tüm TCP birleştiricilerdeki boşlukları atlayıp teslim eder.
    pub fn flush_all(&mut self) {
        for f in self.flows.values_mut() {
            flush_flow(f);
        }
    }

    /// Paketi işler. TCP/UDP olmayan (veya IP parçası, ICMP içindeki) paketler
    /// için `None`.
    pub fn process(
        &mut self,
        pkt_no: u64,
        pkt: &RawPacket,
        dis: &Dissection,
    ) -> Option<PacketAnalysis> {
        let seg = parse(pkt, dis)?;
        self.expire(pkt.ts);
        self.tick += 1;
        let (key, key_dir) = FlowKey::new(seg.proto, seg.src, seg.dst);
        let id = self.lookup(&key, &seg, pkt.ts);
        let tick = self.tick;
        let cfg_ooo = self.cfg.ooo_threshold;
        let flow = self.flows.get_mut(&id)?;
        self.lru.remove(&flow.lru);
        flow.lru = tick;
        self.lru.insert(tick, id);

        let dir = if seg.src == flow.client {
            Dir::Client
        } else {
            Dir::Server
        };
        let di = dir.index();
        flow.packets[di] += 1;
        flow.bytes[di] += u64::from(pkt.orig_len);
        if pkt.ts > flow.last {
            flow.last = pkt.ts;
        }
        if pkt.ts < flow.first {
            flow.first = pkt.ts;
        }

        let tcp = if let (Some(t), Some(ts)) = (&mut flow.tcp, seg.tcp) {
            let (info, out) = analyze(t, dir, &ts, seg.payload, pkt_no, pkt.ts, cfg_ooo);
            deliver(&mut flow.stream, dir, out, pkt_no);
            if matches!(t.state, TcpState::Closed | TcpState::Reset) {
                flush_flow(flow);
            }
            Some(info)
        } else {
            flow.stream.push_data(dir, seg.payload, pkt_no, false);
            None
        };
        Some(PacketAnalysis {
            stream: id,
            key,
            key_dir,
            dir,
            tcp,
        })
    }

    /// Anahtarın akışını bulur ya da yenisini açar.
    fn lookup(&mut self, key: &FlowKey, seg: &Seg<'_>, ts: SystemTime) -> StreamId {
        if let Some(&id) = self.by_key.get(key) {
            let reuse = match (self.flows.get(&id).and_then(|f| f.tcp.as_ref()), seg.tcp) {
                // Kapanmış akışta yeni SYN (farklı ISN): port yeniden kullanımı.
                (Some(t), Some(s)) => {
                    !(matches!(t.state, TcpState::Closed | TcpState::Reset)
                        && s.flags & (SYN | ACK) == SYN
                        && t.dirs.iter().all(|d| d.isn != s.seq))
                }
                _ => true,
            };
            if reuse && self.flows.contains_key(&id) {
                return id;
            }
        }
        while self.flows.len() >= self.cfg.max_flows {
            let Some((_, old)) = self.lru.pop_first() else {
                break;
            };
            self.remove(old);
        }
        let pi = usize::from(seg.proto == Proto::Udp);
        let id = StreamId {
            proto: seg.proto,
            index: self.next_index[pi],
        };
        self.next_index[pi] = self.next_index[pi].wrapping_add(1);
        // SYN-ACK ile başlayan akışta istemci hedeftir.
        let client = match seg.tcp {
            Some(t) if t.flags & (SYN | ACK) == SYN | ACK => seg.dst,
            _ => seg.src,
        };
        let gap = self.cfg.gap_threshold;
        let tcp = seg.tcp.map(|_| TcpFlow {
            dirs: [TcpDir::default(); 2],
            reasm: [Reassembler::new(gap), Reassembler::new(gap)],
            state: TcpState::Established,
        });
        self.flows.insert(
            id,
            Flow {
                key: *key,
                client,
                first: ts,
                last: ts,
                packets: [0; 2],
                bytes: [0; 2],
                lru: 0,
                tcp,
                stream: Stream::new(id, self.cfg.max_buffer),
            },
        );
        self.by_key.insert(*key, id);
        id
    }

    fn remove(&mut self, id: StreamId) {
        if let Some(f) = self.flows.remove(&id) {
            self.lru.remove(&f.lru);
            if self.by_key.get(&f.key) == Some(&id) {
                self.by_key.remove(&f.key);
            }
            self.evicted += 1;
        }
    }

    /// Zaman aşımına uğrayan akışları LRU başından atar.
    fn expire(&mut self, now: SystemTime) {
        let Some(limit) = self.cfg.idle_timeout else {
            return;
        };
        while let Some((_, &id)) = self.lru.first_key_value() {
            let stale = self
                .flows
                .get(&id)
                .is_none_or(|f| now.duration_since(f.last).is_ok_and(|d| d > limit));
            if !stale {
                break;
            }
            self.lru.pop_first();
            self.remove(id);
        }
    }
}

fn conversation_of(id: StreamId, f: &Flow) -> Conversation {
    Conversation {
        stream: id,
        key: f.key,
        client: f.client,
        server: if f.client == f.key.a {
            f.key.b
        } else {
            f.key.a
        },
        packets: f.packets,
        bytes: f.bytes,
        first: f.first,
        last: f.last,
        duration: f.last.duration_since(f.first).unwrap_or_default(),
        state: f.tcp.as_ref().map(|t| t.state),
    }
}

fn deliver(stream: &mut Stream, dir: Dir, out: Vec<Delivery>, pkt_no: u64) {
    for d in out {
        match d {
            Delivery::Data { data, pkt } => stream.push_data(dir, &data, pkt, true),
            Delivery::Lost(n) => stream.push_lost(dir, n, pkt_no),
        }
    }
}

fn flush_flow(f: &mut Flow) {
    let Some(t) = f.tcp.as_mut() else { return };
    for dir in [Dir::Client, Dir::Server] {
        let mut out = Vec::new();
        t.reasm[dir.index()].flush(&mut out);
        let pkt = out
            .iter()
            .find_map(|d| match d {
                Delivery::Data { pkt, .. } => Some(*pkt),
                Delivery::Lost(_) => None,
            })
            .unwrap_or(0);
        deliver(&mut f.stream, dir, out, pkt);
    }
}

/// Tek TCP segmentini analiz eder ve birleştiriciye verir.
#[allow(clippy::too_many_lines)]
fn analyze(
    t: &mut TcpFlow,
    dir: Dir,
    seg: &TcpSeg,
    payload: &[u8],
    pkt_no: u64,
    ts: SystemTime,
    ooo: Duration,
) -> (TcpInfo, Vec<Delivery>) {
    let (si, oi) = (dir.index(), dir.opposite().index());
    let fl = seg.flags;
    let (syn, fin, rst, ackf) = (fl & SYN != 0, fl & FIN != 0, fl & RST != 0, fl & ACK != 0);
    let ctl = syn || fin || rst;
    let seglen = seg.len + u32::from(syn) + u32::from(fin);
    let mut flags = Vec::new();

    let mut syn_retrans = false;
    if syn {
        let s = &t.dirs[si];
        if s.syn && s.isn == seg.seq {
            syn_retrans = true;
        } else {
            t.dirs[si] = TcpDir::start(seg.seq, true, seg.wscale);
        }
    } else if !t.dirs[si].init {
        t.dirs[si] = TcpDir::start(seg.seq, false, None);
    }

    let o = t.dirs[oi];
    let both_ws = t.dirs[0].wscale.is_some() && t.dirs[1].wscale.is_some();
    let shift = |d: &TcpDir| {
        if both_ws {
            u32::from(d.wscale.unwrap_or(0).min(14))
        } else {
            0
        }
    };
    let o_win = u32::from(o.last_win) << shift(&o);
    let window = if syn {
        u32::from(seg.win)
    } else {
        u32::from(seg.win) << shift(&t.dirs[si])
    };

    let s = &mut t.dirs[si];
    let next = s.next_seq;
    let zwp = seg.len == 1 && seg.seq == next && o.ack_valid && o.last_win == 0;
    if zwp {
        flags.push(TcpAnalysis::ZeroWindowProbe);
    }
    if seg.win == 0 && !ctl {
        flags.push(TcpAnalysis::ZeroWindow);
    }
    if !ctl && seq_gt(seg.seq, next) {
        flags.push(TcpAnalysis::PreviousSegmentNotCaptured);
    }
    let keepalive = seg.len <= 1 && !ctl && seg.seq == next.wrapping_sub(1);
    if keepalive {
        flags.push(TcpAnalysis::KeepAlive);
    }
    if seg.len > 0
        && !zwp
        && o.ack_valid
        && seg.seq.wrapping_add(seg.len) == o.last_ack.wrapping_add(o_win)
    {
        flags.push(TcpAnalysis::WindowFull);
    }
    if ackf
        && seg.len == 0
        && !ctl
        && !keepalive
        && s.ack_valid
        && seg.ack == s.last_ack
        && seg.win == s.last_win
    {
        s.dup += 1;
        flags.push(TcpAnalysis::DuplicateAck(s.dup));
    } else if ackf && (!s.ack_valid || seg.ack != s.last_ack) {
        s.dup = 0;
    }
    if ackf && o.init && seq_gt(seg.ack, o.next_seq) {
        flags.push(TcpAnalysis::AckedUnseenSegment);
    }

    // Veri ofseti (SYN'deki veri ISN+1'den başlar).
    let off = s.offset(seg.seq) + i64::from(syn);
    let (off, payload) = if off < 0 {
        let skip = usize::try_from(-off).unwrap_or(usize::MAX);
        (0, payload.get(skip..).unwrap_or(&[]))
    } else {
        (off.unsigned_abs(), payload)
    };
    let reasm = &mut t.reasm[si];

    if syn_retrans {
        flags.push(TcpAnalysis::Retransmission);
    } else if seglen > 0 && !keepalive && !zwp && seq_lt(seg.seq, next) {
        let fills_hole = !payload.is_empty() && reasm.is_new(off, payload.len());
        let recent = s
            .max_ts
            .is_none_or(|m| ts.duration_since(m).map_or(true, |d| d < ooo));
        let end = seg.seq.wrapping_add(seglen);
        let a = if o.dup >= 2 && seg.seq == o.last_ack {
            TcpAnalysis::FastRetransmission
        } else if fills_hole && recent {
            TcpAnalysis::OutOfOrder
        } else if o.ack_valid && !seq_gt(end, o.last_ack) {
            TcpAnalysis::SpuriousRetransmission
        } else {
            TcpAnalysis::Retransmission
        };
        flags.push(a);
    }
    if rst {
        flags.push(TcpAnalysis::Rst);
    }

    // Durum güncelle.
    let end = seg.seq.wrapping_add(seglen);
    if seq_gt(end, s.next_seq) {
        s.next_seq = end;
        s.max_ts = Some(ts);
    }
    if ackf {
        s.last_ack = seg.ack;
        s.last_win = seg.win;
        s.ack_valid = true;
    }
    if fin {
        s.fin = true;
    }
    let rel_seq = seg.seq.wrapping_sub(s.isn);
    let both_fin = s.fin && o.fin;
    t.state = if rst || t.state == TcpState::Reset {
        TcpState::Reset
    } else if both_fin || t.state == TcpState::Closed {
        TcpState::Closed
    } else if syn && !ackf {
        TcpState::SynSent
    } else {
        TcpState::Established
    };

    let mut out = Vec::new();
    reasm.insert(off, payload, pkt_no, &mut out);

    let info = TcpInfo {
        rel_seq,
        rel_ack: (ackf && o.init).then(|| seg.ack.wrapping_sub(o.isn)),
        next_rel_seq: rel_seq.wrapping_add(seglen),
        len: seg.len,
        window,
        analysis: flags,
    };
    (info, out)
}

fn ip_of(l: &Layer, name: &str) -> Option<IpAddr> {
    match l.find(name)?.value {
        FieldValue::Ipv4(a) => Some(IpAddr::V4(a)),
        FieldValue::Ipv6(a) => Some(IpAddr::V6(a)),
        _ => None,
    }
}

fn num(l: &Layer, name: &str) -> Option<u64> {
    l.find(name)?.value.as_u64()
}

fn u16_of(l: &Layer, name: &str) -> Option<u16> {
    num(l, name).and_then(|v| u16::try_from(v).ok())
}

fn u32_of(l: &Layer, name: &str) -> Option<u32> {
    num(l, name).and_then(|v| u32::try_from(v).ok())
}

/// Dissection'dan L3/L4 bilgilerini çıkarır.
fn parse<'a>(pkt: &'a RawPacket, dis: &Dissection) -> Option<Seg<'a>> {
    let li = dis
        .layers
        .iter()
        .position(|l| l.protocol == "tcp" || l.protocol == "udp")?;
    let below = dis.layers.get(..li)?;
    if below
        .iter()
        .any(|l| l.protocol == "icmp" || l.protocol == "icmpv6")
    {
        return None;
    }
    let ip = below
        .iter()
        .rev()
        .find(|l| l.protocol == "ip" || l.protocol == "ipv6")?;
    let p = if ip.protocol == "ip" { "ip" } else { "ipv6" };
    let sip = ip_of(ip, &format!("{p}.src"))?;
    let dip = ip_of(ip, &format!("{p}.dst"))?;
    let l4 = dis.layers.get(li)?;
    let data = pkt.data.as_slice();
    if l4.protocol == "tcp" {
        let hdr = usize::from(u16_of(l4, "tcp.hdr_len")?);
        let len = u32_of(l4, "tcp.len")?;
        let start = l4.offset + hdr;
        let end = start.saturating_add(usize::try_from(len).unwrap_or(usize::MAX));
        let payload = data.get(start.min(data.len())..end.min(data.len()))?;
        let seg = TcpSeg {
            seq: u32_of(l4, "tcp.seq")?,
            ack: u32_of(l4, "tcp.ack")?,
            flags: u16_of(l4, "tcp.flags")?,
            win: u16_of(l4, "tcp.window_size")?,
            len,
            wscale: num(l4, "tcp.options.wscale.shift").and_then(|v| u8::try_from(v).ok()),
        };
        Some(Seg {
            proto: Proto::Tcp,
            src: SocketAddr::new(sip, u16_of(l4, "tcp.srcport")?),
            dst: SocketAddr::new(dip, u16_of(l4, "tcp.dstport")?),
            payload,
            tcp: Some(seg),
        })
    } else {
        let ulen = usize::from(u16_of(l4, "udp.length")?);
        let start = l4.offset + 8;
        let end = (l4.offset + ulen).min(data.len());
        let payload = data.get(start.min(end)..end)?;
        Some(Seg {
            proto: Proto::Udp,
            src: SocketAddr::new(sip, u16_of(l4, "udp.srcport")?),
            dst: SocketAddr::new(dip, u16_of(l4, "udp.dstport")?),
            payload,
            tcp: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrapping_compare() {
        assert!(seq_lt(0xffff_fff0, 0x10));
        assert!(seq_gt(0x10, 0xffff_fff0));
        assert!(!seq_lt(5, 5));
        assert!(seq_lt(1, 2));
    }

    #[test]
    fn offset_unwraps() {
        let mut d = TcpDir::start(0xffff_ff00, true, None);
        assert_eq!(d.offset(0xffff_ff01), 0);
        assert_eq!(d.offset(0x0000_0001), 0x100);
        assert_eq!(d.offset(0xffff_ff81), 0x80);
        // 4 GiB'ı aşan akış.
        let mut d = TcpDir::start(0, false, None);
        for i in 1..=8u64 {
            let seq = u32::try_from((i << 30) & 0xffff_ffff).unwrap();
            assert_eq!(d.offset(seq), i64::try_from(i << 30).unwrap());
        }
    }

    #[test]
    fn config_validation() {
        assert!(FlowTable::with_config(Config::default()).is_ok());
        let bad = Config {
            max_flows: 0,
            ..Config::default()
        };
        assert!(matches!(
            FlowTable::with_config(bad),
            Err(FlowError::InvalidConfig(_))
        ));
        let bad = Config {
            gap_threshold: 10,
            max_buffer: 5,
            ..Config::default()
        };
        assert!(FlowTable::with_config(bad).is_err());
    }
}
