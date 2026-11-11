use std::fs::File;
use std::io::BufReader;
use std::os::unix::fs::FileExt;
use std::path::Path;
use std::time::SystemTime;

use pakiz_dissect::RawPacket;

use crate::{CaptureReader, Error, Result};

/// Bir paketin dosyadaki yeri ve üst bilgisi (veri belleğe alınmaz).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IndexEntry {
    /// Paket verisinin dosya ofseti.
    pub offset: u64,
    /// Dosyadaki bayt sayısı.
    pub cap_len: u32,
    /// Kablodaki orijinal uzunluk.
    pub orig_len: u32,
    /// Zaman damgası.
    pub ts: SystemTime,
    /// Arayüz id (pcap için 0).
    pub ifindex: u32,
}

/// Büyük dosyalar için: paket ofset indeksi + gerektiğinde `pread`.
///
/// İndeksleme artımlıdır ([`IndexedFile::index_more`]); arka planda parça parça
/// ilerletilebilir. Tarama bir hatayla durursa o ana kadarki paketler kullanılabilir
/// kalır ve tarama sonlanmış sayılır.
pub struct IndexedFile {
    file: File,
    reader: Option<CaptureReader<BufReader<File>>>,
    entries: Vec<IndexEntry>,
    file_len: u64,
}

impl IndexedFile {
    /// Dosyayı açar, başlığı doğrular; henüz paket indekslemez.
    ///
    /// # Errors
    /// G/Ç hatası veya geçersiz başlık.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let file = File::open(path)?;
        let file_len = file.metadata()?.len();
        let reader = CaptureReader::from_reader(BufReader::new(file.try_clone()?))?;
        Ok(Self {
            file,
            reader: Some(reader),
            entries: Vec::new(),
            file_len,
        })
    }

    /// En fazla `n` paket daha indeksler; eklenen sayıyı döner (0 → tarama bitti).
    ///
    /// # Errors
    /// Kesik/bozuk kayıt; hata sonrası tarama durur, önceki girdiler korunur.
    pub fn index_more(&mut self, n: usize) -> Result<usize> {
        let Some(reader) = self.reader.as_mut() else {
            return Ok(0);
        };
        let before = self.entries.len();
        while self.entries.len() - before < n {
            match reader.next_record() {
                Ok(Some(m)) => self.entries.push(IndexEntry {
                    offset: m.offset,
                    cap_len: m.cap_len,
                    orig_len: m.orig_len,
                    ts: m.ts,
                    ifindex: m.ifindex,
                }),
                Ok(None) => {
                    self.reader = None;
                    break;
                }
                Err(e) => {
                    self.reader = None;
                    return Err(e);
                }
            }
        }
        Ok(self.entries.len() - before)
    }

    /// Tüm dosyayı indeksler; `progress(taranan_bayt, toplam_bayt)` aralıklarla çağrılır.
    ///
    /// # Errors
    /// Bkz. [`IndexedFile::index_more`].
    pub fn index_all(&mut self, mut progress: impl FnMut(u64, u64)) -> Result<()> {
        while self.index_more(4096)? > 0 {
            progress(self.bytes_scanned(), self.file_len);
        }
        progress(self.file_len, self.file_len);
        Ok(())
    }

    /// Tarama bitti mi (EOF ya da hata).
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.reader.is_none()
    }

    /// Taranan bayt (tarama bittiyse dosya boyu).
    #[must_use]
    pub fn bytes_scanned(&self) -> u64 {
        self.reader
            .as_ref()
            .map_or(self.file_len, CaptureReader::position)
    }

    /// Dosya boyu.
    #[must_use]
    pub fn file_len(&self) -> u64 {
        self.file_len
    }

    /// İndekslenmiş paket sayısı.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Hiç paket indekslenmedi mi.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// İndeks girdileri.
    #[must_use]
    pub fn entries(&self) -> &[IndexEntry] {
        &self.entries
    }

    /// `i`. paketi diskten okur.
    ///
    /// # Errors
    /// Aralık dışı indeks veya G/Ç hatası.
    pub fn get(&self, i: usize) -> Result<RawPacket> {
        let e = *self.entries.get(i).ok_or(Error::OutOfRange {
            index: i,
            len: self.entries.len(),
        })?;
        let mut data = vec![0u8; e.cap_len as usize];
        self.file.read_exact_at(&mut data, e.offset)?;
        Ok(RawPacket {
            ts: e.ts,
            data,
            orig_len: e.orig_len,
            ifindex: e.ifindex,
        })
    }
}
