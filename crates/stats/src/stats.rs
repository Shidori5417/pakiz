//! Trafik istatistikleri toplayıcısı.

use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};
use std::time::{SystemTime, UNIX_EPOCH};

use pakiz_dissect::{Dissection, RawPacket};

use crate::table::{Table, Weighted};
use crate::{Endpoints, Transport};

/// Paket + bayt sayacı.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Counter {
    pub packets: u64,
    pub bytes: u64,
}

impl Counter {
    fn hit(&mut self, len: u64) {
        self.packets += 1;
        self.bytes += len;
    }

    pub(crate) fn add(&mut self, o: Counter) {
        self.packets += o.packets;
        self.bytes += o.bytes;
    }
}

impl Weighted for Counter {
    fn weight(&self) -> Counter {
        *self
    }
}

/// Bir IP adresinin gönderdiği / aldığı trafik.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Talker {
    pub tx: Counter,
    pub rx: Counter,
}

impl Weighted for Talker {
    fn weight(&self) -> Counter {
        let mut c = self.tx;
        c.add(self.rx);
        c
    }
}

/// IP çifti konuşması (`a <= b`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Conversation<A> {
    pub a: A,
    pub b: A,
    pub a_to_b: Counter,
    pub b_to_a: Counter,
    pub first: SystemTime,
    pub last: SystemTime,
}

impl<A> Weighted for Conversation<A> {
    fn weight(&self) -> Counter {
        let mut c = self.a_to_b;
        c.add(self.b_to_a);
        c
    }
}

/// IP:port çifti konuşması.
pub type EndpointConversation = Conversation<SocketAddr>;

/// Protokol hiyerarşisinde bir düğüm.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HierarchyNode {
    /// `eth/ip/tcp/tls` biçiminde yol.
    pub path: String,
    /// Kök = 0.
    pub depth: usize,
    /// Son bileşen (ör. `tls`).
    pub protocol: String,
    pub counter: Counter,
}

/// Toplayıcı ayarları.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StatsConfig {
    /// Zaman serisi halka uzunluğu (saniye).
    pub window_secs: usize,
    /// Her tablo için en fazla giriş.
    pub max_entries: usize,
}

impl Default for StatsConfig {
    fn default() -> Self {
        Self {
            window_secs: 300,
            max_entries: 10_000,
        }
    }
}

/// Trafik istatistikleri toplayıcısı.
#[derive(Debug, Clone)]
pub struct Stats {
    // Zaman serisi: halka, `head_sec` en yeni saniye.
    ring: Vec<Counter>,
    head_sec: Option<u64>,
    peak: Counter,
    total: Counter,
    first: Option<SystemTime>,
    last: Option<SystemTime>,
    hierarchy: BTreeMap<String, Counter>,
    top_proto: BTreeMap<&'static str, Counter>,
    talkers: Table<IpAddr, Talker>,
    ip_convs: Table<((), IpAddr, IpAddr), Conversation<IpAddr>>,
    ep_convs: Table<(Transport, SocketAddr, SocketAddr), EndpointConversation>,
    ports: Table<(Transport, u16), Counter>,
}

impl Default for Stats {
    fn default() -> Self {
        Self::new(StatsConfig::default())
    }
}

fn epoch_secs(ts: SystemTime) -> u64 {
    ts.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

impl Stats {
    #[must_use]
    pub fn new(cfg: StatsConfig) -> Self {
        let m = cfg.max_entries;
        Self {
            ring: vec![Counter::default(); cfg.window_secs.max(1)],
            head_sec: None,
            peak: Counter::default(),
            total: Counter::default(),
            first: None,
            last: None,
            hierarchy: BTreeMap::new(),
            top_proto: BTreeMap::new(),
            talkers: Table::new(m),
            ip_convs: Table::new(m),
            ep_convs: Table::new(m),
            ports: Table::new(m),
        }
    }

    /// `RawPacket` kolaylığı: kablo uzunluğu ve zaman damgasıyla kaydeder.
    pub fn record_packet(&mut self, p: &RawPacket, d: &Dissection) {
        self.record(p.ts, u64::from(p.orig_len), d);
    }

    /// Bir paketi tüm istatistiklere işler.
    pub fn record(&mut self, ts: SystemTime, len: u64, d: &Dissection) {
        self.total.hit(len);
        self.first = Some(self.first.map_or(ts, |f| f.min(ts)));
        self.last = Some(self.last.map_or(ts, |l| l.max(ts)));
        self.record_series(epoch_secs(ts), len);
        self.record_protocols(len, d);
        if let Some(ep) = Endpoints::from_dissection(d) {
            self.record_endpoints(ts, len, &ep);
        }
    }

    fn slot(&self, sec: u64) -> usize {
        let n = self.ring.len() as u64;
        usize::try_from(sec % n).unwrap_or(0)
    }

    /// Halkayı `sec` saniyesine ilerletir (aradaki kovalar sıfırlanır).
    /// Trafik yokken grafiğin akması için UI tick'inde de çağrılabilir.
    pub fn advance_to(&mut self, ts: SystemTime) {
        self.advance_sec(epoch_secs(ts));
    }

    fn advance_sec(&mut self, sec: u64) {
        let n = self.ring.len() as u64;
        match self.head_sec {
            None => {
                self.head_sec = Some(sec);
            }
            Some(h) if sec > h => {
                if sec - h >= n {
                    self.ring.fill(Counter::default());
                } else {
                    for s in h + 1..=sec {
                        let i = self.slot(s);
                        self.ring[i] = Counter::default();
                    }
                }
                self.head_sec = Some(sec);
            }
            Some(_) => {}
        }
    }

    fn record_series(&mut self, sec: u64, len: u64) {
        self.advance_sec(sec);
        let Some(h) = self.head_sec else { return };
        // Pencereden eski paket: seriye girmez.
        if h - sec.min(h) >= self.ring.len() as u64 {
            return;
        }
        let i = self.slot(sec);
        self.ring[i].hit(len);
        let c = self.ring[i];
        self.peak.packets = self.peak.packets.max(c.packets);
        self.peak.bytes = self.peak.bytes.max(c.bytes);
    }

    fn series(&self, f: impl Fn(&Counter) -> u64) -> Vec<u64> {
        let Some(h) = self.head_sec else {
            return vec![0; self.ring.len()];
        };
        let n = self.ring.len() as u64;
        (0..n)
            .map(|k| {
                let sec = (h + 1 + k).wrapping_sub(n);
                if sec > h {
                    0 // epoch öncesi (çok erken saniyeler)
                } else {
                    f(&self.ring[self.slot(sec)])
                }
            })
            .collect()
    }

    /// Saniyelik paket sayısı, eskiden yeniye (uzunluk = pencere).
    #[must_use]
    pub fn pps_series(&self) -> Vec<u64> {
        self.series(|c| c.packets)
    }

    /// Saniyelik bayt sayısı, eskiden yeniye.
    #[must_use]
    pub fn bps_series(&self) -> Vec<u64> {
        self.series(|c| c.bytes)
    }

    /// Toplam paket/bayt.
    #[must_use]
    pub fn total(&self) -> Counter {
        self.total
    }

    /// En yoğun saniyenin paket ve bayt değeri (ayrı ayrı maksimum).
    #[must_use]
    pub fn peak(&self) -> Counter {
        self.peak
    }

    /// İlk ve son paket zamanı.
    #[must_use]
    pub fn time_range(&self) -> Option<(SystemTime, SystemTime)> {
        Some((self.first?, self.last?))
    }

    /// Ortalama (paket/sn, bayt/sn) — ilk ile son paket arası, en az 1 sn.
    #[must_use]
    #[allow(clippy::cast_precision_loss)]
    pub fn average(&self) -> (f64, f64) {
        let secs = self
            .time_range()
            .and_then(|(f, l)| l.duration_since(f).ok())
            .map_or(1.0, |d| d.as_secs_f64().max(1.0));
        (
            self.total.packets as f64 / secs,
            self.total.bytes as f64 / secs,
        )
    }

    fn record_protocols(&mut self, len: u64, d: &Dissection) {
        let mut path = String::new();
        for l in d.layers.iter().filter(|l| l.protocol != "frame") {
            if !path.is_empty() {
                path.push('/');
            }
            path.push_str(l.protocol);
            if let Some(c) = self.hierarchy.get_mut(path.as_str()) {
                c.hit(len);
            } else {
                let mut c = Counter::default();
                c.hit(len);
                self.hierarchy.insert(path.clone(), c);
            }
        }
        if let Some(top) = d.layers.last() {
            self.top_proto.entry(top.protocol).or_default().hit(len);
        }
    }

    /// Wireshark "Protocol Hierarchy": ağaç sırasında (önce derinlik) düğümler.
    /// Her düğüm, yolu bu önekle başlayan tüm paketleri sayar.
    #[must_use]
    pub fn protocol_hierarchy(&self) -> Vec<HierarchyNode> {
        // '/' tüm protokol adı karakterlerinden küçük olmadığı için
        // bileşen listesine göre sırala.
        let mut v: Vec<_> = self
            .hierarchy
            .iter()
            .map(|(p, c)| {
                let parts: Vec<&str> = p.split('/').collect();
                HierarchyNode {
                    path: p.clone(),
                    depth: parts.len() - 1,
                    protocol: parts.last().map_or_else(String::new, |s| (*s).to_owned()),
                    counter: *c,
                }
            })
            .collect();
        v.sort_by(|a, b| a.path.split('/').cmp(b.path.split('/')));
        v
    }

    /// Düz dağılım: en üst protokol başına, bayta göre azalan.
    #[must_use]
    pub fn protocol_distribution(&self) -> Vec<(&'static str, Counter)> {
        let mut v: Vec<_> = self.top_proto.iter().map(|(p, c)| (*p, *c)).collect();
        v.sort_by_key(|&(_, c)| std::cmp::Reverse((c.bytes, c.packets)));
        v
    }

    fn record_endpoints(&mut self, ts: SystemTime, len: u64, ep: &Endpoints) {
        self.talkers.entry(ep.src, Talker::default).tx.hit(len);
        self.talkers.entry(ep.dst, Talker::default).rx.hit(len);
        conv_hit(&mut self.ip_convs, (), ep.src, ep.dst, ts, len);
        if let (Some((t, _, dp)), Some(s), Some(d)) = (ep.l4, ep.src_sock(), ep.dst_sock()) {
            conv_hit(&mut self.ep_convs, t, s, d, ts, len);
            self.ports.entry((t, dp), Counter::default).hit(len);
        }
    }

    /// Bayta göre en çok trafik yapan `k` IP (gönderilen + alınan).
    #[must_use]
    pub fn top_talkers(&self, k: usize) -> Vec<(IpAddr, Talker)> {
        self.talkers
            .top_n(k)
            .into_iter()
            .map(|(a, t)| (*a, *t))
            .collect()
    }

    /// Bayta göre en büyük `k` IP konuşması.
    #[must_use]
    pub fn top_ip_conversations(&self, k: usize) -> Vec<Conversation<IpAddr>> {
        self.ip_convs
            .top_n(k)
            .into_iter()
            .map(|(_, c)| *c)
            .collect()
    }

    /// Bayta göre en büyük `k` IP:port konuşması.
    #[must_use]
    pub fn top_endpoint_conversations(&self, k: usize) -> Vec<(Transport, EndpointConversation)> {
        self.ep_convs
            .top_n(k)
            .into_iter()
            .map(|((t, _, _), c)| (*t, *c))
            .collect()
    }

    /// Bayta göre en çok kullanılan `k` hedef port.
    #[must_use]
    pub fn top_ports(&self, k: usize) -> Vec<(Transport, u16, Counter)> {
        self.ports
            .top_n(k)
            .into_iter()
            .map(|((t, p), c)| (*t, *p, *c))
            .collect()
    }

    /// Ham tablolar (UI'nin tam liste / "diğer" gösterimi için).
    #[must_use]
    pub fn talkers(&self) -> &Table<IpAddr, Talker> {
        &self.talkers
    }

    #[must_use]
    pub fn ip_conversations(&self) -> &Table<((), IpAddr, IpAddr), Conversation<IpAddr>> {
        &self.ip_convs
    }

    #[must_use]
    pub fn endpoint_conversations(
        &self,
    ) -> &Table<(Transport, SocketAddr, SocketAddr), EndpointConversation> {
        &self.ep_convs
    }

    #[must_use]
    pub fn ports(&self) -> &Table<(Transport, u16), Counter> {
        &self.ports
    }
}

/// Yönsüz anahtarla konuşma sayacını günceller.
fn conv_hit<T, A>(
    table: &mut Table<(T, A, A), Conversation<A>>,
    tag: T,
    src: A,
    dst: A,
    ts: SystemTime,
    len: u64,
) where
    T: std::hash::Hash + Eq + Clone,
    A: std::hash::Hash + Eq + Ord + Copy,
{
    let (a, b) = if src <= dst { (src, dst) } else { (dst, src) };
    let c = table.entry((tag, a, b), || Conversation {
        a,
        b,
        a_to_b: Counter::default(),
        b_to_a: Counter::default(),
        first: ts,
        last: ts,
    });
    if src == a {
        c.a_to_b.hit(len);
    } else {
        c.b_to_a.hit(len);
    }
    c.first = c.first.min(ts);
    c.last = c.last.max(ts);
}

#[cfg(test)]
mod tests {
    use super::*;
    use pakiz_dissect::{RawPacket, Registry};
    use std::time::Duration;

    /// eth + ipv4 + tcp/udp çerçevesi (yük yok).
    fn frame(tcp: bool, src: [u8; 4], dst: [u8; 4], sp: u16, dp: u16) -> Dissection {
        let mut f = vec![0u8; 12];
        f.extend_from_slice(&[0x08, 0x00]);
        let l4len: u16 = if tcp { 20 } else { 8 };
        f.extend_from_slice(&[0x45, 0]);
        f.extend_from_slice(&(20 + l4len).to_be_bytes());
        f.extend_from_slice(&[0, 1, 0, 0, 64, if tcp { 6 } else { 17 }, 0, 0]);
        f.extend_from_slice(&src);
        f.extend_from_slice(&dst);
        f.extend_from_slice(&sp.to_be_bytes());
        f.extend_from_slice(&dp.to_be_bytes());
        if tcp {
            f.extend_from_slice(&[0, 0, 0, 1, 0, 0, 0, 0, 0x50, 0x10, 0xff, 0xff, 0, 0, 0, 0]);
        } else {
            f.extend_from_slice(&[0, 8, 0, 0]);
        }
        Registry::default().dissect(&RawPacket {
            ts: UNIX_EPOCH,
            orig_len: 60,
            data: f,
            ifindex: 1,
        })
    }

    fn at(s: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(1_000_000 + s)
    }

    fn tcp(src: [u8; 4], dst: [u8; 4], sp: u16, dp: u16) -> Dissection {
        frame(true, src, dst, sp, dp)
    }

    #[test]
    fn series_bucket_shift() {
        let mut s = Stats::new(StatsConfig {
            window_secs: 4,
            max_entries: 100,
        });
        let d = tcp([10, 0, 0, 1], [10, 0, 0, 2], 1000, 80);
        assert_eq!(s.pps_series(), vec![0; 4]);
        s.record(at(0), 100, &d);
        s.record(at(0), 50, &d);
        s.record(at(1), 10, &d);
        assert_eq!(s.pps_series(), vec![0, 0, 2, 1]);
        assert_eq!(s.bps_series(), vec![0, 0, 150, 10]);
        // 2 sn boşluk: aradaki kova sıfırlanır, eski kovalar sola kayar.
        s.record(at(3), 7, &d);
        assert_eq!(s.pps_series(), vec![2, 1, 0, 1]);
        // Pencere dışı geç gelen paket seriye girmez ama toplama girer.
        s.record(at(0) - Duration::from_secs(10), 1, &d);
        assert_eq!(s.pps_series(), vec![2, 1, 0, 1]);
        assert_eq!(s.total().packets, 5);
        // Halkayı tamamen aşan sıçrama.
        s.advance_to(at(100));
        assert_eq!(s.pps_series(), vec![0; 4]);
        assert_eq!(
            s.peak(),
            Counter {
                packets: 2,
                bytes: 150
            }
        );
        // Geç gelen ama pencere içindeki paket doğru kovaya.
        s.record(at(98), 3, &d);
        assert_eq!(s.pps_series(), vec![0, 1, 0, 0]);
    }

    #[test]
    fn average() {
        let mut s = Stats::default();
        let d = tcp([10, 0, 0, 1], [10, 0, 0, 2], 1000, 80);
        s.record(at(0), 100, &d);
        s.record(at(4), 300, &d);
        let (pps, bps) = s.average();
        assert!((pps - 0.5).abs() < 1e-9);
        assert!((bps - 100.0).abs() < 1e-9);
    }

    #[test]
    fn protocol_hierarchy() {
        let mut s = Stats::default();
        s.record(at(0), 100, &tcp([10, 0, 0, 1], [10, 0, 0, 2], 1000, 80));
        s.record(
            at(0),
            50,
            &frame(false, [10, 0, 0, 1], [10, 0, 0, 2], 1000, 9999),
        );
        let h: Vec<_> = s
            .protocol_hierarchy()
            .into_iter()
            .map(|n| (n.path, n.depth, n.counter.packets, n.counter.bytes))
            .collect();
        assert_eq!(h[0], ("eth".to_owned(), 0, 2, 150));
        assert_eq!(h[1], ("eth/ip".to_owned(), 1, 2, 150));
        assert_eq!(h[2], ("eth/ip/tcp".to_owned(), 2, 1, 100));
        assert!(h.iter().any(|n| n.0.starts_with("eth/ip/udp") && n.3 == 50));
        let flat = s.protocol_distribution();
        assert_eq!(
            flat[0],
            (
                "tcp",
                Counter {
                    packets: 1,
                    bytes: 100
                }
            )
        );
    }

    #[test]
    fn hierarchy_tree_order() {
        let mut s = Stats::default();
        let mut d = tcp([10, 0, 0, 1], [10, 0, 0, 2], 1000, 80);
        s.record(at(0), 1, &d);
        // "eth/ip-x" '/'dan küçük karakter içerse bile çocuklar ebeveynin hemen altında.
        d.layers[2].protocol = "ip-x";
        s.record(at(0), 1, &d);
        let paths: Vec<_> = s.protocol_hierarchy().into_iter().map(|n| n.path).collect();
        assert_eq!(
            paths,
            ["eth", "eth/ip", "eth/ip/tcp", "eth/ip-x", "eth/ip-x/tcp"]
        );
    }

    #[test]
    fn top_n_sorting_and_conversations() {
        let mut s = Stats::default();
        let (a, b, c) = ([10, 0, 0, 1], [10, 0, 0, 2], [10, 0, 0, 3]);
        s.record(at(0), 100, &tcp(a, b, 1000, 80));
        s.record(at(1), 400, &tcp(b, a, 80, 1000));
        s.record(at(2), 10, &tcp(c, b, 2000, 443));
        let t = s.top_talkers(2);
        assert_eq!(t.len(), 2);
        assert_eq!(t[0].0, IpAddr::from(b));
        assert_eq!(t[0].1.weight().bytes, 510);
        assert_eq!(t[1].0, IpAddr::from(a));
        assert_eq!(t[1].1.tx.bytes, 100);
        assert_eq!(t[1].1.rx.bytes, 400);

        let cv = s.top_ip_conversations(10);
        assert_eq!(cv.len(), 2);
        assert_eq!((cv[0].a, cv[0].b), (IpAddr::from(a), IpAddr::from(b)));
        assert_eq!(
            cv[0].a_to_b,
            Counter {
                packets: 1,
                bytes: 100
            }
        );
        assert_eq!(
            cv[0].b_to_a,
            Counter {
                packets: 1,
                bytes: 400
            }
        );
        assert_eq!((cv[0].first, cv[0].last), (at(0), at(1)));

        let ec = s.top_endpoint_conversations(1);
        assert_eq!(ec[0].0, Transport::Tcp);
        assert_eq!(ec[0].1.a, "10.0.0.1:1000".parse().unwrap());
        assert_eq!(ec[0].1.weight().packets, 2);
    }

    #[test]
    fn port_distribution() {
        let mut s = Stats::default();
        let (a, b) = ([10, 0, 0, 1], [10, 0, 0, 2]);
        s.record(at(0), 10, &tcp(a, b, 1000, 443));
        s.record(at(0), 10, &tcp(a, b, 1001, 443));
        s.record(at(0), 5, &frame(false, a, b, 5000, 53));
        s.record(at(0), 50, &tcp(a, b, 1002, 22));
        let p = s.top_ports(10);
        assert_eq!(
            p[0],
            (
                Transport::Tcp,
                22,
                Counter {
                    packets: 1,
                    bytes: 50
                }
            )
        );
        assert_eq!(
            p[1],
            (
                Transport::Tcp,
                443,
                Counter {
                    packets: 2,
                    bytes: 20
                }
            )
        );
        assert_eq!(p[2].0, Transport::Udp);
        assert_eq!(p[2].1, 53);
    }

    #[test]
    fn memory_limit_other() {
        let mut s = Stats::new(StatsConfig {
            window_secs: 10,
            max_entries: 10,
        });
        for i in 0..50u8 {
            s.record(
                at(0),
                u64::from(i) + 1,
                &tcp([10, 0, 1, i], [10, 0, 0, 1], 1000, u16::from(i)),
            );
        }
        assert!(s.ports().len() <= 10);
        assert!(s.talkers().len() <= 10);
        let kept: u64 = s.ports().iter().map(|(_, c)| c.bytes).sum();
        assert_eq!(kept + s.ports().other().bytes, s.total().bytes);
        // En büyük port kalmalı.
        assert_eq!(s.top_ports(1)[0].1, 49);
    }
}
