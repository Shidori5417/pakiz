//! pakiz-dissect: ham paket tipi ve (ileride) protokol ayrıştırıcıları.

use std::time::SystemTime;

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
