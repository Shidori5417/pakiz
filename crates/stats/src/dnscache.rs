//! DNS cevaplarından IP → ad önbelleği (LRU).

use std::cell::Cell;
use std::collections::HashMap;
use std::net::IpAddr;

use pakiz_dissect::{Dissection, Field, FieldValue};

#[derive(Debug, Clone)]
struct Entry {
    name: String,
    used: Cell<u64>,
}

/// A/AAAA kayıtlarından IP → sorgulanan ad eşlemesi.
///
/// CNAME zincirinde IP, zincirin sonundaki ada değil ilk sorgu adına
/// (`dns.qry.name`) bağlanır. En fazla `max` giriş; aşılınca en uzun süredir
/// kullanılmayan girişler atılır.
#[derive(Debug, Clone)]
pub struct DnsCache {
    map: HashMap<IpAddr, Entry>,
    max: usize,
    clock: Cell<u64>,
}

impl Default for DnsCache {
    fn default() -> Self {
        Self::new(10_000)
    }
}

fn str_of(f: &Field) -> Option<&str> {
    match &f.value {
        FieldValue::Str(s) => Some(s),
        _ => None,
    }
}

fn collect_rrs<'a>(f: &'a Field, out: &mut Vec<&'a Field>) {
    if f.name == "dns.rr" {
        out.push(f);
    } else if f.name != "dns.authorities" && f.name != "dns.additionals" {
        for c in &f.children {
            collect_rrs(c, out);
        }
    }
}

impl DnsCache {
    #[must_use]
    pub fn new(max: usize) -> Self {
        Self {
            map: HashMap::new(),
            max: max.max(1),
            clock: Cell::new(0),
        }
    }

    fn tick(&self) -> u64 {
        let t = self.clock.get() + 1;
        self.clock.set(t);
        t
    }

    /// DNS cevabıysa A/AAAA kayıtlarını önbelleğe ekler; eklenen sayıyı döner.
    pub fn record(&mut self, d: &Dissection) -> usize {
        let Some(dns) = d.layer("dns") else { return 0 };
        if !matches!(
            dns.find("dns.flags.response").map(|f| &f.value),
            Some(FieldValue::Bool(true))
        ) {
            return 0;
        }
        let qname = dns.find("dns.qry.name").and_then(str_of);
        let mut rrs = Vec::new();
        collect_rrs(&dns.fields, &mut rrs);
        let mut n = 0;
        for rr in rrs.into_iter().filter(|r| !r.malformed) {
            let ip = rr.children.iter().find_map(|c| match (c.name, &c.value) {
                ("dns.a", FieldValue::Ipv4(a)) => Some(IpAddr::V4(*a)),
                ("dns.aaaa", FieldValue::Ipv6(a)) => Some(IpAddr::V6(*a)),
                _ => None,
            });
            let name = qname.or_else(|| rr.find("dns.resp.name").and_then(str_of));
            if let (Some(ip), Some(name)) = (ip, name) {
                self.insert(ip, name);
                n += 1;
            }
        }
        n
    }

    /// Elle ekleme.
    pub fn insert(&mut self, ip: IpAddr, name: &str) {
        let used = Cell::new(self.tick());
        if let Some(e) = self.map.get_mut(&ip) {
            name.clone_into(&mut e.name);
            e.used = used;
            return;
        }
        if self.map.len() >= self.max {
            self.evict();
        }
        self.map.insert(
            ip,
            Entry {
                name: name.to_owned(),
                used,
            },
        );
    }

    /// En eski ~%10'u atar (amortize O(1)).
    fn evict(&mut self) {
        let mut v: Vec<(u64, IpAddr)> = self.map.iter().map(|(k, e)| (e.used.get(), *k)).collect();
        v.sort_unstable();
        for (_, k) in v.into_iter().take((self.max / 10).max(1)) {
            self.map.remove(&k);
        }
    }

    /// IP için bilinen ad (erişim LRU sırasını günceller).
    #[must_use]
    pub fn name_for(&self, ip: IpAddr) -> Option<&str> {
        let e = self.map.get(&ip)?;
        e.used.set(self.tick());
        Some(&e.name)
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.map.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::dissect;

    // dissect crate'inin DNS test baytları (dns.rs: RESPONSE, RICH, QUERY).
    const QUERY: &str = "a0b1c2d3e4f53c22fb1a2b3c0800450000391c46400040114cacc0a8010a08080808c8220035002583e8123401000001000000000000076578616d706c6503636f6d0000010001";
    const RESPONSE: &str = "a0b1c2d3e4f53c22fb1a2b3c0800450000491c46400040114c9c08080808c0a8010a0035c82200350543123481800001000100000000076578616d706c6503636f6d0000010001c00c0001000100000e1000045db8d822";
    const RICH: &str = "a0b1c2d3e4f53c22fb1a2b3c08004500011e1c46400040114bc708080808c0a8010a0035c822010ad44ebeef8180000100070001000003777777076578616d706c6503636f6d0000010001c00c000500010000012c0002c010c010000100010000012c00045db8d822c010001c00010000012c001026062800022000010248189325c81946c010000f00010000012c0009000a046d61696cc010c010001000010000012c000c0b763d73706631202d616c6c045f736970045f756470c010002100010000012c000c0000000513c403736970c010c010004100010000012c000b0001000001000302683200c010000600010000012c0035026e73056963616e6e036f726700036e6f6303646e73056963616e6e036f72670078a3f17500001c2000000e100012750000000e10";

    #[test]
    fn a_record() {
        let mut c = DnsCache::default();
        assert_eq!(c.record(&dissect(QUERY)), 0);
        assert_eq!(c.record(&dissect(RESPONSE)), 1);
        assert_eq!(
            c.name_for("93.184.216.34".parse().unwrap()),
            Some("example.com")
        );
        assert_eq!(c.name_for("1.1.1.1".parse().unwrap()), None);
    }

    #[test]
    fn cname_chain_uses_query_name() {
        let mut c = DnsCache::default();
        assert_eq!(c.record(&dissect(RICH)), 2);
        assert_eq!(
            c.name_for("93.184.216.34".parse().unwrap()),
            Some("www.example.com")
        );
        assert_eq!(
            c.name_for("2606:2800:220:1:248:1893:25c8:1946".parse().unwrap()),
            Some("www.example.com")
        );
    }

    #[test]
    fn lru_eviction() {
        let mut c = DnsCache::new(3);
        let ip = |n: u8| IpAddr::from([10, 0, 0, n]);
        c.insert(ip(1), "a");
        c.insert(ip(2), "b");
        c.insert(ip(3), "c");
        assert_eq!(c.name_for(ip(1)), Some("a")); // 1 artık en yeni
        c.insert(ip(4), "d"); // 2 atılır
        assert_eq!(c.len(), 3);
        assert_eq!(c.name_for(ip(2)), None);
        assert_eq!(c.name_for(ip(1)), Some("a"));
        assert_eq!(c.name_for(ip(4)), Some("d"));
    }
}
