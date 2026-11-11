//! pakiz-storage: pcap / pcapng okuma-yazma ve büyük dosyalar için ofset indeksi.
//!
//! Dış pcap kütüphanesi kullanılmaz; biçimler elle çözülür/yazılır.

mod error;
mod index;
mod read;
mod write;

use std::path::Path;

pub use error::{Error, Result};
pub use index::{IndexEntry, IndexedFile};
pub use read::{CaptureReader, LINKTYPE_ETHERNET};
pub use write::{create, CaptureWriter, PcapWriter, PcapngWriter, TsResolution};

/// Yakalama dosyası biçimi.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    /// Klasik libpcap biçimi.
    Pcap,
    /// pcapng (blok tabanlı).
    Pcapng,
}

impl Format {
    /// Uzantıdan biçim çıkarır: `.pcapng` → [`Format::Pcapng`], diğer her şey → [`Format::Pcap`].
    #[must_use]
    pub fn from_path(path: impl AsRef<Path>) -> Self {
        match path.as_ref().extension().and_then(|e| e.to_str()) {
            Some(e) if e.eq_ignore_ascii_case("pcapng") => Self::Pcapng,
            _ => Self::Pcap,
        }
    }
}
