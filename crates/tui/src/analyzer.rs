//! Paket işleme hattı: dissect → akış analizi → istatistik → DNS önbelleği
//! → (canlıda) süreç eşleme → sentetik analiz alanları. TUI ve `--no-tui`
//! aynı hattı kullanır.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::time::{Duration, Instant};

use pakiz_dissect::{Dissection, RawPacket, Registry};
use pakiz_filter::FieldCatalog;
use pakiz_flow::{annotate, FlowTable, FlowTag, StreamId};
use pakiz_stats::dnscache::DnsCache;
use pakiz_stats::procmap::ProcessResolver;
use pakiz_stats::Stats;

/// Yerleşik dissector alanları + akış analizinin sentetik alanları.
#[must_use]
pub fn catalog() -> FieldCatalog {
    let mut defs = Registry::default().all_fields();
    defs.extend_from_slice(pakiz_flow::FIELDS);
    FieldCatalog::new(defs)
}

/// Tek paketin hat çıktısı.
#[derive(Debug, Clone)]
pub struct Analyzed {
    /// Sentetik akış alanları eklenmiş ayrıştırma.
    pub dissection: Dissection,
    pub flow: Option<FlowTag>,
    /// Yerel süreç adı (yalnızca süreç eşleme açıkken).
    pub process: Option<String>,
}

/// Kümülatif analiz durumu (paket deposundan bağımsız; halka tampondan düşen
/// paketler akış/istatistikleri etkilemez).
pub struct Analyzer {
    registry: Registry,
    pub flows: FlowTable,
    pub stats: Stats,
    pub dns: DnsCache,
    procs: Option<ProcessResolver>,
    /// Akış başına ilk tam soket eşleşmesinin süreci (bir bağlantı = bir süreç).
    proc_by_stream: HashMap<StreamId, String>,
    /// İlk tam eşleşme denemesinde zorla yenileme yapılmış akışlar.
    proc_tried: HashSet<StreamId>,
    last_forced: Option<Instant>,
}

/// Yeni akış için zorla yenilemeler arası en kısa süre.
const FORCED_REFRESH: Duration = Duration::from_millis(100);

/// Akış → süreç önbelleği bu boyutu aşınca temizlenir.
const PROC_CACHE_MAX: usize = 65_536;

impl Default for Analyzer {
    fn default() -> Self {
        Self::new(FlowTable::new())
    }
}

impl Analyzer {
    #[must_use]
    pub fn new(flows: FlowTable) -> Self {
        Self {
            registry: Registry::default(),
            flows,
            stats: Stats::default(),
            dns: DnsCache::default(),
            procs: None,
            proc_by_stream: HashMap::new(),
            proc_tried: HashSet::new(),
            last_forced: None,
        }
    }

    /// Canlı yakalama: yerel soket → süreç eşlemeyi açar.
    pub fn enable_processes(&mut self) {
        // Kısa ömürlü yerel bağlantıları (curl) yakalamak için sık yenile.
        self.procs = Some(ProcessResolver::default().with_min_interval(Duration::from_millis(250)));
    }

    #[must_use]
    pub fn processes_enabled(&self) -> bool {
        self.procs.is_some()
    }

    /// Süreç tablosunu (hız sınırlı) yeniler.
    pub fn refresh_processes(&mut self) {
        if let Some(p) = self.procs.as_mut() {
            p.refresh();
        }
    }

    #[must_use]
    pub fn registry(&self) -> &Registry {
        &self.registry
    }

    /// Paketi bir kez ayrıştırıp tüm kümülatif durumlara işler.
    pub fn analyze(&mut self, number: u64, raw: &RawPacket) -> Analyzed {
        let mut d = self.registry.dissect_numbered(raw, Some(number));
        let flow = self
            .flows
            .process(number, raw, &d)
            .map(|a| FlowTag::from(&a));
        self.stats.record_packet(raw, &d);
        self.dns.record(&d);
        let process = self.lookup_process(flow.as_ref(), &d);
        if let Some(t) = &flow {
            annotate(&mut d, t);
        }
        Analyzed {
            dissection: d,
            flow,
            process,
        }
    }

    /// Önce akış önbelleği, sonra tam soket eşleşmesi (önbelleğe alınır), en
    /// son yerel adres / dinleyen soket (önbelleğe alınmaz). Yeni akışın ilk
    /// ıskalamasında tablo (periyodik yenilemenin hız sınırını beklemeden)
    /// bir kez zorla yenilenir: kısa ömürlü bağlantının soketi hâlâ açıkken.
    fn lookup_process(&mut self, flow: Option<&FlowTag>, d: &Dissection) -> Option<String> {
        let procs = self.procs.as_mut()?;
        if let Some(name) = flow.and_then(|t| self.proc_by_stream.get(&t.stream)) {
            return Some(name.clone());
        }
        let mut name = procs.lookup_packet_exact(d).map(|p| p.name.clone());
        if name.is_none() {
            if let Some(t) = flow {
                let due = self
                    .last_forced
                    .is_none_or(|i| i.elapsed() >= FORCED_REFRESH);
                if due && self.proc_tried.insert(t.stream) {
                    self.last_forced = Some(Instant::now());
                    procs.force_refresh();
                    name = procs.lookup_packet_exact(d).map(|p| p.name.clone());
                }
            }
        }
        match (name, flow) {
            (Some(n), Some(t)) => {
                if self.proc_by_stream.len() >= PROC_CACHE_MAX {
                    self.proc_by_stream.clear();
                    self.proc_tried.clear();
                }
                self.proc_by_stream.insert(t.stream, n.clone());
                Some(n)
            }
            (Some(n), None) => Some(n),
            (None, _) => procs.lookup_packet(d).map(|p| p.name.clone()),
        }
    }

    /// Yeniden ayrıştırma (filtre/ağaç): saklanan akış özeti alanlara eklenir.
    #[must_use]
    pub fn dissect(&self, raw: &RawPacket, number: u64, flow: Option<&FlowTag>) -> Dissection {
        let mut d = self.registry.dissect_numbered(raw, Some(number));
        if let Some(t) = flow {
            annotate(&mut d, t);
        }
        d
    }

    /// DNS önbelleğindeki ad.
    #[must_use]
    pub fn name_for(&self, ip: IpAddr) -> Option<&str> {
        self.dns.name_for(ip)
    }

    /// Adres metni bir IP ise ve ad biliniyorsa adı, değilse metni döner.
    #[must_use]
    pub fn resolve<'a>(&'a self, addr: &'a str) -> &'a str {
        addr.parse::<IpAddr>()
            .ok()
            .and_then(|ip| self.name_for(ip))
            .unwrap_or(addr)
    }
}
