//! Halka tamponlu paket deposu.

use std::collections::VecDeque;
use std::time::SystemTime;

use pakiz_dissect::{RawPacket, Summary};

/// Depolanan tek paket: ham veri + önceden hesaplanmış özet.
#[derive(Debug, Clone)]
pub struct Entry {
    /// 1'den başlayan paket numarası (düşen paketlerden sonra da artmaya devam eder).
    pub number: u64,
    pub raw: RawPacket,
    pub summary: Summary,
    pub malformed: bool,
}

/// En fazla `max` paket tutan halka tampon; dolunca en eski paket düşer.
#[derive(Debug)]
pub struct PacketStore {
    buf: VecDeque<Entry>,
    max: usize,
    next_number: u64,
    evicted: u64,
    first_ts: Option<SystemTime>,
}

impl PacketStore {
    /// Varsayılan maksimum paket sayısı.
    pub const DEFAULT_MAX: usize = 100_000;

    #[must_use]
    pub fn new(max: usize) -> Self {
        Self {
            buf: VecDeque::new(),
            max: max.max(1),
            next_number: 1,
            evicted: 0,
            first_ts: None,
        }
    }

    /// Paketi ekler; taşma olursa düşen paket sayısını (0 veya 1) döner.
    pub fn push(&mut self, raw: RawPacket, summary: Summary, malformed: bool) -> usize {
        self.first_ts.get_or_insert(raw.ts);
        let mut dropped = 0;
        if self.buf.len() >= self.max {
            self.buf.pop_front();
            self.evicted += 1;
            dropped = 1;
        }
        self.buf.push_back(Entry {
            number: self.next_number,
            raw,
            summary,
            malformed,
        });
        self.next_number += 1;
        dropped
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.buf.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    #[must_use]
    pub fn get(&self, idx: usize) -> Option<&Entry> {
        self.buf.get(idx)
    }

    /// Şimdiye kadar eklenen toplam paket.
    #[must_use]
    pub fn total(&self) -> u64 {
        self.next_number - 1
    }

    /// Halka tampon taşmasıyla düşen paket.
    #[must_use]
    pub fn evicted(&self) -> u64 {
        self.evicted
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
