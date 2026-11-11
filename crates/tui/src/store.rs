//! Paket deposu: canlı yakalama için halka tampon, dosya için indeks + lazy okuma.

use std::borrow::Cow;
use std::cell::RefCell;
use std::collections::{HashMap, VecDeque};
use std::time::SystemTime;

use pakiz_dissect::{RawPacket, Registry, Summary};
use pakiz_flow::FlowTag;
use pakiz_storage::IndexedFile;

/// Depolanan tek paket: ham veri + önceden hesaplanmış özet.
#[derive(Debug, Clone)]
pub struct Entry {
    /// 1'den başlayan paket numarası (düşen paketlerden sonra da artmaya devam eder).
    pub number: u64,
    pub raw: RawPacket,
    pub summary: Summary,
    pub malformed: bool,
    /// İlk geçişte üretilen akış/analiz özeti.
    pub flow: Option<FlowTag>,
    /// Canlı yakalamada paketin yerel süreci (bir kez çözülür).
    pub process: Option<String>,
}

/// Dosya modunda diskten okunup ayrıştırılmış paketlerin küçük önbelleği (FIFO tahliye).
struct FileCache {
    map: HashMap<usize, Entry>,
    order: VecDeque<usize>,
}

impl FileCache {
    const CAP: usize = 1024;
}

enum Mode {
    Memory {
        buf: VecDeque<Entry>,
        max: usize,
        evicted: u64,
    },
    File(Box<FileMode>),
}

struct FileMode {
    file: IndexedFile,
    registry: Registry,
    cache: RefCell<FileCache>,
    error: Option<String>,
    /// İndeks sırasıyla analiz edilmiş paketlerin akış özetleri.
    flows: Vec<Option<FlowTag>>,
}

/// Paket deposu. Bellek modunda en fazla `max` paket (halka tampon); dosya modunda
/// yalnızca ofset indeksi tutulur, paketler [`PacketStore::get`] ile diskten okunur.
pub struct PacketStore {
    mode: Mode,
    next_number: u64,
    first_ts: Option<SystemTime>,
}

/// Ayrıştırıp [`Entry`] kurar.
pub(crate) fn make_entry(
    registry: &Registry,
    number: u64,
    raw: RawPacket,
    flow: Option<FlowTag>,
) -> Entry {
    let d = registry.dissect(&raw);
    let malformed = d.layers.iter().any(pakiz_dissect::Layer::is_malformed);
    Entry {
        number,
        raw,
        summary: d.summary,
        malformed,
        flow,
        process: None,
    }
}

impl PacketStore {
    /// Varsayılan maksimum paket sayısı.
    pub const DEFAULT_MAX: usize = 100_000;

    #[must_use]
    pub fn new(max: usize) -> Self {
        Self {
            mode: Mode::Memory {
                buf: VecDeque::new(),
                max: max.max(1),
                evicted: 0,
            },
            next_number: 1,
            first_ts: None,
        }
    }

    /// Dosya modu: halka tampon sınırı uygulanmaz.
    #[must_use]
    pub fn from_file(file: IndexedFile) -> Self {
        Self {
            mode: Mode::File(Box::new(FileMode {
                file,
                registry: Registry::default(),
                cache: RefCell::new(FileCache {
                    map: HashMap::new(),
                    order: VecDeque::new(),
                }),
                error: None,
                flows: Vec::new(),
            })),
            next_number: 1,
            first_ts: None,
        }
    }

    /// Dosya modu mu.
    #[must_use]
    pub fn is_file(&self) -> bool {
        matches!(self.mode, Mode::File(_))
    }

    /// Dosya modunda en fazla `n` paket daha indeksler; eklenen sayıyı döner.
    pub fn index_more(&mut self, n: usize) -> usize {
        let Mode::File(fm) = &mut self.mode else {
            return 0;
        };
        let FileMode { file, error, .. } = &mut **fm;
        let added = match file.index_more(n) {
            Ok(k) => k,
            Err(e) => {
                *error = Some(e.to_string());
                0
            }
        };
        if self.first_ts.is_none() {
            self.first_ts = file.entries().first().map(|e| e.ts);
        }
        added
    }

    /// İndeksleme sürüyorsa yüzde (0..=99); bittiyse ya da bellek modunda `None`.
    #[must_use]
    pub fn index_progress(&self) -> Option<u8> {
        let Mode::File(fm) = &self.mode else {
            return None;
        };
        let file = &fm.file;
        if file.is_complete() {
            return None;
        }
        let pct = file.bytes_scanned().saturating_mul(100) / file.file_len().max(1);
        Some(u8::try_from(pct.min(99)).unwrap_or(99))
    }

    /// Dosya okuma/indeksleme hatası.
    #[must_use]
    pub fn error(&self) -> Option<&str> {
        match &self.mode {
            Mode::File(fm) => fm.error.as_deref(),
            Mode::Memory { .. } => None,
        }
    }

    /// Analizi tamamlanmış paket sayısı (dosyada indeks önünde kalabilir;
    /// bellek modunda her zaman `len`).
    #[must_use]
    pub fn analyzed(&self) -> usize {
        match &self.mode {
            Mode::Memory { buf, .. } => buf.len(),
            Mode::File(fm) => fm.flows.len(),
        }
    }

    /// Dosya modu: sıradaki (`analyzed()`.) paketin akış özetini kaydeder.
    pub fn push_flow(&mut self, flow: Option<FlowTag>) {
        if let Mode::File(fm) = &mut self.mode {
            fm.flows.push(flow);
        }
    }

    /// `idx`. paketin akış özeti (paketi okumadan).
    #[must_use]
    pub fn flow(&self, idx: usize) -> Option<FlowTag> {
        match &self.mode {
            Mode::Memory { buf, .. } => buf.get(idx).and_then(|e| e.flow),
            Mode::File(fm) => fm.flows.get(idx).copied().flatten(),
        }
    }

    /// Paketi ekler (yalnızca bellek modu); taşma olursa düşen paket sayısını (0 veya 1) döner.
    pub fn push(
        &mut self,
        raw: RawPacket,
        summary: Summary,
        malformed: bool,
        flow: Option<FlowTag>,
        process: Option<String>,
    ) -> usize {
        let Mode::Memory { buf, max, evicted } = &mut self.mode else {
            return 0;
        };
        self.first_ts.get_or_insert(raw.ts);
        let mut dropped = 0;
        if buf.len() >= *max {
            buf.pop_front();
            *evicted += 1;
            dropped = 1;
        }
        buf.push_back(Entry {
            number: self.next_number,
            raw,
            summary,
            malformed,
            flow,
            process,
        });
        self.next_number += 1;
        dropped
    }

    #[must_use]
    pub fn len(&self) -> usize {
        match &self.mode {
            Mode::Memory { buf, .. } => buf.len(),
            Mode::File(fm) => fm.file.len(),
        }
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// `idx`. paket. Dosya modunda diskten okunur ve önbelleğe alınır.
    #[must_use]
    pub fn get(&self, idx: usize) -> Option<Cow<'_, Entry>> {
        match &self.mode {
            Mode::Memory { buf, .. } => buf.get(idx).map(Cow::Borrowed),
            Mode::File(fm) => {
                let FileMode {
                    file,
                    registry,
                    cache,
                    flows,
                    ..
                } = &**fm;
                let flow = flows.get(idx).copied().flatten();
                let mut c = cache.borrow_mut();
                if let Some(e) = c.map.get(&idx) {
                    // Analiz önbelleğe alındıktan sonra tamamlanmış olabilir.
                    let mut e = e.clone();
                    e.flow = flow;
                    return Some(Cow::Owned(e));
                }
                let raw = file.get(idx).ok()?;
                let e = make_entry(registry, idx as u64 + 1, raw, flow);
                if c.order.len() >= FileCache::CAP {
                    if let Some(old) = c.order.pop_front() {
                        c.map.remove(&old);
                    }
                }
                c.order.push_back(idx);
                c.map.insert(idx, e.clone());
                Some(Cow::Owned(e))
            }
        }
    }

    /// Ham paketi okur (özet hesaplamadan; dışa aktarma için).
    #[must_use]
    pub fn raw(&self, idx: usize) -> Option<Cow<'_, RawPacket>> {
        match &self.mode {
            Mode::Memory { buf, .. } => buf.get(idx).map(|e| Cow::Borrowed(&e.raw)),
            Mode::File(fm) => fm.file.get(idx).ok().map(Cow::Owned),
        }
    }

    /// Dosya modunda önbellekteki girdi sayısı (testler/teşhis için).
    #[must_use]
    pub fn cached(&self) -> usize {
        match &self.mode {
            Mode::File(fm) => fm.cache.borrow().map.len(),
            Mode::Memory { .. } => 0,
        }
    }

    /// Şimdiye kadar eklenen (dosyada: indekslenen) toplam paket.
    #[must_use]
    pub fn total(&self) -> u64 {
        match &self.mode {
            Mode::Memory { .. } => self.next_number - 1,
            Mode::File(fm) => fm.file.len() as u64,
        }
    }

    /// Depodaki ilk paketin numarası (boşsa bir sonraki eklenecek numara).
    /// `idx`. paketin numarası `first_number() + idx`'tir.
    #[must_use]
    pub fn first_number(&self) -> u64 {
        match &self.mode {
            Mode::Memory { buf, .. } => self.next_number - buf.len() as u64,
            Mode::File(_) => 1,
        }
    }

    /// Bellek modunda bir sonraki [`PacketStore::push`]'un alacağı numara.
    #[must_use]
    pub fn next_number(&self) -> u64 {
        self.next_number
    }

    /// Halka tampon taşmasıyla düşen paket.
    #[must_use]
    pub fn evicted(&self) -> u64 {
        match &self.mode {
            Mode::Memory { evicted, .. } => *evicted,
            Mode::File(_) => 0,
        }
    }

    /// İlk pakete göre göreli zaman (saniye).
    #[must_use]
    pub fn rel_time(&self, e: &Entry) -> f64 {
        self.first_ts
            .and_then(|t0| e.raw.ts.duration_since(t0).ok())
            .unwrap_or_default()
            .as_secs_f64()
    }
}
