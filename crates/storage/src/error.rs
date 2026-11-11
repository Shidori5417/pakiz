/// Depolama hataları.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Alttaki G/Ç hatası.
    #[error("G/Ç hatası: {0}")]
    Io(#[from] std::io::Error),
    /// Dosya pcap/pcapng değil.
    #[error("bilinmeyen dosya biçimi (magic 0x{0:08x})")]
    UnknownMagic(u32),
    /// Ethernet dışı bağlantı katmanı.
    #[error("desteklenmeyen linktype {0} (yalnızca 1/Ethernet destekli)")]
    UnsupportedLinkType(u32),
    /// Dosya bir yapının ortasında bitiyor.
    #[error("dosya kesik: {0} tamamlanmadan bitti")]
    Truncated(&'static str),
    /// Yapısal olarak bozuk veri.
    #[error("bozuk dosya (ofset {offset}): {msg}")]
    Malformed {
        /// Sorunlu yapının dosya ofseti.
        offset: u64,
        /// Açıklama.
        msg: String,
    },
    /// pcapng paketi tanımlanmamış bir arayüze işaret ediyor.
    #[error("tanımsız pcapng arayüz id {0}")]
    UnknownInterface(u32),
    /// `IndexedFile::get` için geçersiz indeks.
    #[error("paket indeksi aralık dışı: {index} (toplam {len})")]
    OutOfRange {
        /// İstenen indeks.
        index: usize,
        /// Mevcut paket sayısı.
        len: usize,
    },
    /// Yazılamayacak kadar büyük paket.
    #[error("paket çok büyük: {0} bayt")]
    TooLarge(usize),
}

/// Kısaltma.
pub type Result<T> = std::result::Result<T, Error>;
