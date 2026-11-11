//! Bellek sınırlı sayaç tablosu.

use std::collections::HashMap;
use std::hash::Hash;

use crate::Counter;

/// Ağırlığı (bayt) olan tablo değeri.
pub trait Weighted {
    /// Bu girişin toplam paket/bayt sayacı.
    fn weight(&self) -> Counter;
}

/// En fazla `max` giriş tutan tablo; aşılınca en az trafikli ~%10 giriş
/// atılıp toplamları [`Table::other`] sayacına eklenir.
#[derive(Debug, Clone)]
pub struct Table<K, V> {
    map: HashMap<K, V>,
    other: Counter,
    max: usize,
}

impl<K: Hash + Eq + Clone, V: Weighted> Table<K, V> {
    #[must_use]
    pub fn new(max: usize) -> Self {
        Self {
            map: HashMap::new(),
            other: Counter::default(),
            max: max.max(1),
        }
    }

    /// Girişi döndürür; yoksa `init` ile oluşturur (gerekirse budar).
    pub fn entry(&mut self, key: K, init: impl FnOnce() -> V) -> &mut V {
        if !self.map.contains_key(&key) && self.map.len() >= self.max {
            self.prune();
        }
        self.map.entry(key).or_insert_with(init)
    }

    fn prune(&mut self) {
        let drop_n = (self.max / 10).max(1);
        let mut ws: Vec<(u64, u64, K)> = self
            .map
            .iter()
            .map(|(k, v)| {
                let w = v.weight();
                (w.bytes, w.packets, k.clone())
            })
            .collect();
        ws.sort_unstable_by_key(|&(b, p, _)| (b, p));
        for (_, _, k) in ws.into_iter().take(drop_n) {
            if let Some(v) = self.map.remove(&k) {
                self.other.add(v.weight());
            }
        }
    }

    /// Atılan girişlerin toplamı ("diğer").
    #[must_use]
    pub fn other(&self) -> Counter {
        self.other
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.map.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    pub fn get(&self, key: &K) -> Option<&V> {
        self.map.get(key)
    }

    pub fn iter(&self) -> impl Iterator<Item = (&K, &V)> {
        self.map.iter()
    }

    /// Ağırlığa (bayt, sonra paket) göre azalan ilk `k` giriş.
    #[must_use]
    pub fn top_n(&self, k: usize) -> Vec<(&K, &V)> {
        let mut v: Vec<_> = self.map.iter().collect();
        v.sort_by(|a, b| {
            let (wa, wb) = (a.1.weight(), b.1.weight());
            (wb.bytes, wb.packets).cmp(&(wa.bytes, wa.packets))
        });
        v.truncate(k);
        v
    }
}
