//! pakiz-dissect: ham paket tipi, `Dissector` trait'i, `Registry` ve protokoller.
//!
//! Tüm ayrıştırma `&[u8]` üzerinde zero-copy yapılır; kısa/bozuk veri asla
//! panic'e yol açmaz, ilgili alan `malformed = true` olarak işaretlenir.

// Protokol kodunda kısa adlar (r, l, t...) ve uzun dissect fonksiyonları bilinçli.
#![allow(
    clippy::too_many_lines,
    clippy::many_single_char_names,
    clippy::similar_names
)]
#![cfg_attr(test, allow(clippy::unwrap_used))]

use std::time::SystemTime;

mod field;
pub mod proto;
mod reader;
mod registry;

pub use field::{fmt_mac, Field, FieldDef, FieldType, FieldValue, Layer};
pub use reader::Reader;
pub use registry::{Ctx, DissectResult, Dissection, Dissector, NextHint, Registry, Summary};

/// Yakalanmış ham çerçeve.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawPacket {
    /// Kernel zaman damgası.
    pub ts: SystemTime,
    /// Yakalanan bayt (snaplen ile kırpılmış olabilir).
    pub data: Vec<u8>,
    /// Kablodaki orijinal uzunluk.
    pub orig_len: u32,
    /// Arayüz indeksi.
    pub ifindex: u32,
}

#[cfg(test)]
pub(crate) mod testutil {
    use super::{Dissection, RawPacket, Registry};
    use std::time::SystemTime;

    pub fn hex(s: &str) -> Vec<u8> {
        let s: String = s.split_whitespace().collect();
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    pub fn pkt(data: Vec<u8>) -> RawPacket {
        RawPacket {
            ts: SystemTime::UNIX_EPOCH,
            orig_len: u32::try_from(data.len()).unwrap(),
            data,
            ifindex: 1,
        }
    }

    pub fn dissect(h: &str) -> Dissection {
        Registry::default().dissect(&pkt(hex(h)))
    }

    /// Her uzunluktaki önek için dissect: panic olmamalı, frame katmanı hep olmalı.
    pub fn sweep(h: &str) {
        let reg = Registry::default();
        let data = hex(h);
        for n in 0..=data.len() {
            let d = reg.dissect(&pkt(data[..n].to_vec()));
            assert_eq!(d.layers[0].protocol, "frame");
            let _ = d.summary.info.len();
        }
    }
}
