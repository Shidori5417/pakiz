//! Tek yönlü TCP bayt akışı yeniden birleştirme.
//!
//! Politika:
//! - Ofsetler akışın ilk veri baytına göre (`u64`, sarmalamadan bağımsız).
//! - **İlk gelen kazanır**: bir bayt bir kez alındıysa (teslim edilmiş ya da
//!   bekleyen) sonradan gelen örtüşen segment onu değiştirmez; yalnızca
//!   henüz görülmemiş aralıklar eklenir. Retransmission'lar böylece atlanır.
//! - Sıra dışı segmentler `BTreeMap`'te bekler. Bekleyen bayt
//!   `gap_threshold`'u aşarsa ilk boşluk kayıp kabul edilir:
//!   [`Delivery::Lost`] üretilir ve birleştirme boşluğun ötesinden sürer.
//! - [`Reassembler::flush`] (FIN/RST, yakalama sonu) kalan tüm boşlukları atlar.

use std::collections::BTreeMap;

use crate::{u64_of, usize_of};

/// Birleştiricinin çıktısı (teslim sırasıyla).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Delivery {
    /// Ardışık yeni veri; `pkt` bu baytları ilk taşıyan paket numarası.
    Data { data: Vec<u8>, pkt: u64 },
    /// Atlanan (yakalanmamış) bayt sayısı.
    Lost(u64),
}

/// Tek yön için yeniden birleştirici.
#[derive(Debug, Clone)]
pub struct Reassembler {
    next: u64,
    pending: BTreeMap<u64, (Vec<u8>, u64)>,
    pending_bytes: usize,
    gap_threshold: usize,
}

impl Reassembler {
    /// `gap_threshold`: bu kadar bayt boşluğun ötesinde beklerse boşluk atlanır.
    #[must_use]
    pub fn new(gap_threshold: usize) -> Self {
        Self {
            next: 0,
            pending: BTreeMap::new(),
            pending_bytes: 0,
            gap_threshold,
        }
    }

    /// Sıradaki beklenen ofset (bu ofsete kadar her şey teslim/atlandı).
    #[must_use]
    pub fn next_offset(&self) -> u64 {
        self.next
    }

    /// Sıra dışı bekleyen bayt sayısı.
    #[must_use]
    pub fn pending_bytes(&self) -> usize {
        self.pending_bytes
    }

    /// `[off, off+len)` aralığında daha önce hiç alınmamış bayt var mı?
    #[must_use]
    pub fn is_new(&self, off: u64, len: usize) -> bool {
        let end = off.saturating_add(u64_of(len));
        let mut cur = off.max(self.next);
        if cur >= end {
            return false;
        }
        for (s, e) in self.overlapping(cur, end) {
            if s > cur {
                return true;
            }
            cur = cur.max(e);
            if cur >= end {
                return false;
            }
        }
        cur < end
    }

    /// `[start, end)` ile örtüşen bekleyen aralıklar (sıralı).
    fn overlapping(&self, start: u64, end: u64) -> Vec<(u64, u64)> {
        let mut v = Vec::new();
        if let Some((&s, (d, _))) = self.pending.range(..start).next_back() {
            let e = s + u64_of(d.len());
            if e > start {
                v.push((s, e));
            }
        }
        v.extend(
            self.pending
                .range(start..end)
                .map(|(&s, (d, _))| (s, s + u64_of(d.len()))),
        );
        v
    }

    /// Segment ekler; yeni ardışık hale gelen veriyi `out`'a yazar.
    pub fn insert(&mut self, off: u64, data: &[u8], pkt: u64, out: &mut Vec<Delivery>) {
        let end = off.saturating_add(u64_of(data.len()));
        if end <= self.next || data.is_empty() {
            return;
        }
        let start = off.max(self.next);
        let mut cur = start;
        for (s, e) in self.overlapping(start, end) {
            if s > cur {
                self.put(off, data, cur, s, pkt);
            }
            cur = cur.max(e);
        }
        if cur < end {
            self.put(off, data, cur, end, pkt);
        }
        self.drain(out);
        while self.pending_bytes > self.gap_threshold {
            self.skip_gap(out);
        }
    }

    /// Kalan tüm boşlukları atlayıp bekleyenleri teslim eder.
    pub fn flush(&mut self, out: &mut Vec<Delivery>) {
        while !self.pending.is_empty() {
            self.skip_gap(out);
        }
    }

    fn put(&mut self, base: u64, data: &[u8], s: u64, e: u64, pkt: u64) {
        let a = usize_of(s - base);
        let b = usize_of(e - base).min(data.len());
        if let Some(piece) = data.get(a..b) {
            self.pending_bytes += piece.len();
            self.pending.insert(s, (piece.to_vec(), pkt));
        }
    }

    fn drain(&mut self, out: &mut Vec<Delivery>) {
        while let Some(entry) = self.pending.first_entry() {
            if *entry.key() != self.next {
                break;
            }
            let (data, pkt) = entry.remove();
            self.pending_bytes -= data.len();
            self.next += u64_of(data.len());
            out.push(Delivery::Data { data, pkt });
        }
    }

    fn skip_gap(&mut self, out: &mut Vec<Delivery>) {
        if let Some((&k, _)) = self.pending.first_key_value() {
            if k > self.next {
                out.push(Delivery::Lost(k - self.next));
                self.next = k;
            }
            self.drain(out);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn collect(out: &[Delivery]) -> Vec<u8> {
        let mut v = Vec::new();
        for d in out {
            match d {
                Delivery::Data { data, .. } => v.extend_from_slice(data),
                Delivery::Lost(n) => v.extend(std::iter::repeat_n(b'?', usize_of(*n))),
            }
        }
        v
    }

    #[test]
    fn in_order_and_ooo() {
        let mut r = Reassembler::new(1 << 20);
        let mut out = Vec::new();
        r.insert(5, b"fghij", 2, &mut out);
        assert!(out.is_empty());
        assert_eq!(r.pending_bytes(), 5);
        r.insert(0, b"abcde", 1, &mut out);
        assert_eq!(collect(&out), b"abcdefghij");
        assert_eq!(r.next_offset(), 10);
        assert_eq!(r.pending_bytes(), 0);
    }

    #[test]
    fn first_wins_overlap() {
        let mut r = Reassembler::new(1 << 20);
        let mut out = Vec::new();
        r.insert(4, b"EFGH", 1, &mut out);
        // [2,10) örtüşür: 4..8 korunur, 2..4 ve 8..10 yeni.
        r.insert(2, b"xxxxxxIJ", 2, &mut out);
        r.insert(0, b"ab", 3, &mut out);
        assert_eq!(collect(&out), b"abxxEFGHIJ");
        // Teslim edilmiş bölgeye yeniden yazma etkisiz.
        out.clear();
        r.insert(0, b"ZZZZZZZZZZZZ", 4, &mut out);
        assert_eq!(collect(&out), b"ZZ");
    }

    #[test]
    fn is_new_detection() {
        let mut r = Reassembler::new(1 << 20);
        let mut out = Vec::new();
        r.insert(0, b"abc", 1, &mut out);
        r.insert(6, b"ghi", 2, &mut out);
        assert!(!r.is_new(0, 3));
        assert!(!r.is_new(6, 3));
        assert!(r.is_new(3, 3));
        assert!(r.is_new(2, 5));
        assert!(!r.is_new(7, 1));
        assert!(r.is_new(8, 2));
    }

    #[test]
    fn gap_threshold_skips() {
        let mut r = Reassembler::new(4);
        let mut out = Vec::new();
        r.insert(0, b"ab", 1, &mut out);
        r.insert(5, b"fgh", 2, &mut out);
        assert_eq!(out.len(), 1);
        r.insert(8, b"ij", 3, &mut out);
        assert_eq!(out[1], Delivery::Lost(3));
        assert_eq!(collect(&out), b"ab???fghij");
        // Atlanan bölgeye geç gelen veri yok sayılır.
        out.clear();
        r.insert(2, b"cde", 4, &mut out);
        assert!(out.is_empty());
    }

    #[test]
    fn flush_marks_all_gaps() {
        let mut r = Reassembler::new(1 << 20);
        let mut out = Vec::new();
        r.insert(2, b"c", 1, &mut out);
        r.insert(5, b"f", 2, &mut out);
        r.flush(&mut out);
        assert_eq!(collect(&out), b"??c??f");
    }
}
