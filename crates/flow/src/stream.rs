//! Follow Stream verisi ve görüntüleme yardımcıları.

use std::collections::VecDeque;
use std::fmt::{self, Write as _};

use crate::{Dir, Proto};

/// Akış kimliği: protokol + protokol içinde artan sıra (`tcp.stream` / `udp.stream`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct StreamId {
    pub proto: Proto,
    pub index: u32,
}

impl fmt::Display for StreamId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}.stream {}",
            if self.proto == Proto::Tcp {
                "tcp"
            } else {
                "udp"
            },
            self.index
        )
    }
}

/// Veri yerine geçen işaret.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Marker {
    /// Yakalanmamış (kayıp) bayt sayısı.
    Lost(u64),
    /// Yön başına bellek sınırı nedeniyle atılan bayt sayısı.
    Dropped(u64),
}

/// Follow görünümünde tek parça: aynı yöndeki ardışık veri.
/// `marker` doluysa `data` boştur ve parça bir boşluğu temsil eder.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Chunk<'a> {
    pub dir: Dir,
    pub data: &'a [u8],
    /// Bu parçanın ilk baytını taşıyan paket numarası.
    pub first_pkt: u64,
    pub marker: Option<Marker>,
}

#[derive(Debug, Clone)]
struct Stored {
    dir: Dir,
    data: Vec<u8>,
    first_pkt: u64,
    marker: Option<Marker>,
}

/// Bir akışın birleştirilmiş, yön değişimlerine göre parçalanmış verisi.
#[derive(Debug, Clone)]
pub struct Stream {
    id: StreamId,
    chunks: VecDeque<Stored>,
    stored: [usize; 2],
    dropped: [u64; 2],
    max_buffer: usize,
}

impl Stream {
    pub(crate) fn new(id: StreamId, max_buffer: usize) -> Self {
        Self {
            id,
            chunks: VecDeque::new(),
            stored: [0; 2],
            dropped: [0; 2],
            max_buffer,
        }
    }

    #[must_use]
    pub fn id(&self) -> StreamId {
        self.id
    }

    /// Birleştirilmiş sırada parçalar. TCP'de aynı yöndeki ardışık veri tek
    /// parçadır; UDP'de her datagram ayrı parçadır.
    pub fn chunks(&self) -> impl Iterator<Item = Chunk<'_>> {
        self.chunks.iter().map(|c| Chunk {
            dir: c.dir,
            data: &c.data,
            first_pkt: c.first_pkt,
            marker: c.marker,
        })
    }

    /// Uygulama katmanı kancası: bir yönün bellekte tutulan birleşik baytları
    /// (boşluk işaretleri atlanır).
    #[must_use]
    pub fn data(&self, dir: Dir) -> Vec<u8> {
        let mut v = Vec::with_capacity(self.stored[dir.index()]);
        for c in self.chunks.iter().filter(|c| c.dir == dir) {
            v.extend_from_slice(&c.data);
        }
        v
    }

    /// Bellek sınırı nedeniyle atılan bayt sayısı.
    #[must_use]
    pub fn dropped_bytes(&self, dir: Dir) -> u64 {
        self.dropped[dir.index()]
    }

    /// Bellekte tutulan veri baytı.
    #[must_use]
    pub fn stored_bytes(&self, dir: Dir) -> usize {
        self.stored[dir.index()]
    }

    /// Veri ekler; `merge` ise son parça aynı yöndeyse ona eklenir.
    pub(crate) fn push_data(&mut self, dir: Dir, data: &[u8], pkt: u64, merge: bool) {
        if data.is_empty() {
            return;
        }
        match self.chunks.back_mut() {
            Some(c) if merge && c.dir == dir && c.marker.is_none() => {
                c.data.extend_from_slice(data);
            }
            _ => self.chunks.push_back(Stored {
                dir,
                data: data.to_vec(),
                first_pkt: pkt,
                marker: None,
            }),
        }
        self.stored[dir.index()] += data.len();
        self.enforce(dir);
    }

    pub(crate) fn push_lost(&mut self, dir: Dir, n: u64, pkt: u64) {
        if let Some(Stored {
            dir: d,
            marker: Some(Marker::Lost(m)),
            ..
        }) = self.chunks.back_mut()
        {
            if *d == dir {
                *m += n;
                return;
            }
        }
        self.chunks.push_back(Stored {
            dir,
            data: Vec::new(),
            first_pkt: pkt,
            marker: Some(Marker::Lost(n)),
        });
    }

    /// Yön sınırı aşıldıysa o yönün en eski verisini atar ve işaretler.
    fn enforce(&mut self, dir: Dir) {
        let di = dir.index();
        while self.stored[di] > self.max_buffer {
            let Some(i) = self
                .chunks
                .iter()
                .position(|c| c.dir == dir && c.marker.is_none())
            else {
                break;
            };
            let excess = self.stored[di] - self.max_buffer;
            let Some(c) = self.chunks.get_mut(i) else {
                break;
            };
            let take = excess.min(c.data.len());
            c.data.drain(..take);
            let pkt = c.first_pkt;
            let empty = c.data.is_empty();
            self.stored[di] -= take;
            let n = crate::u64_of(take);
            self.dropped[di] += n;
            if empty {
                self.chunks.remove(i);
            }
            let merged = i
                .checked_sub(1)
                .and_then(|p| self.chunks.get_mut(p))
                .and_then(|p| match (&mut p.marker, p.dir == dir) {
                    (Some(Marker::Dropped(m)), true) => Some(m),
                    _ => None,
                })
                .map(|m| *m += n)
                .is_some();
            if !merged {
                self.chunks.insert(
                    i,
                    Stored {
                        dir,
                        data: Vec::new(),
                        first_pkt: pkt,
                        marker: Some(Marker::Dropped(n)),
                    },
                );
            }
        }
    }
}

fn marker_text(m: Marker) -> String {
    match m {
        Marker::Lost(n) => format!("[{n} bayt eksik]"),
        Marker::Dropped(n) => format!("[{n} bayt bellek sınırı nedeniyle atıldı]"),
    }
}

/// ASCII görünümü: yazdırılamayan baytlar `.` olur (`\n` korunur).
#[must_use]
pub fn render_ascii(chunk: &Chunk<'_>) -> String {
    if let Some(m) = chunk.marker {
        return marker_text(m);
    }
    chunk
        .data
        .iter()
        .map(|&b| {
            if b == b'\n' || b.is_ascii_graphic() || b == b' ' {
                char::from(b)
            } else {
                '.'
            }
        })
        .collect()
}

/// Hexdump satırları: `ofset  16 bayt hex  |ascii|`.
#[must_use]
pub fn render_hex(chunk: &Chunk<'_>) -> String {
    if let Some(m) = chunk.marker {
        return marker_text(m);
    }
    let mut s = String::new();
    for (i, line) in chunk.data.chunks(16).enumerate() {
        let _ = write!(s, "{:08x}  ", i * 16);
        for j in 0..16 {
            match line.get(j) {
                Some(b) => {
                    let _ = write!(s, "{b:02x} ");
                }
                None => s.push_str("   "),
            }
            if j == 7 {
                s.push(' ');
            }
        }
        s.push(' ');
        s.push('|');
        s.extend(line.iter().map(|&b| {
            if b.is_ascii_graphic() || b == b' ' {
                char::from(b)
            } else {
                '.'
            }
        }));
        s.push_str("|\n");
    }
    s
}

/// Ham görünüm: tek satır küçük harf hex dizisi.
#[must_use]
pub fn render_raw(chunk: &Chunk<'_>) -> String {
    if let Some(m) = chunk.marker {
        return marker_text(m);
    }
    let mut s = String::with_capacity(chunk.data.len() * 2);
    for b in chunk.data {
        let _ = write!(s, "{b:02x}");
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sid() -> StreamId {
        StreamId {
            proto: Proto::Tcp,
            index: 0,
        }
    }

    #[test]
    fn merge_and_split_by_dir() {
        let mut s = Stream::new(sid(), 1 << 20);
        s.push_data(Dir::Client, b"ab", 1, true);
        s.push_data(Dir::Client, b"cd", 2, true);
        s.push_data(Dir::Server, b"xy", 3, true);
        s.push_lost(Dir::Server, 4, 4);
        s.push_data(Dir::Server, b"z", 4, true);
        let c: Vec<_> = s.chunks().collect();
        assert_eq!(c.len(), 4);
        assert_eq!(c[0].data, b"abcd");
        assert_eq!(c[0].first_pkt, 1);
        assert_eq!(c[2].marker, Some(Marker::Lost(4)));
        assert_eq!(s.data(Dir::Server), b"xyz");
    }

    #[test]
    fn memory_limit_drops_oldest() {
        let mut s = Stream::new(sid(), 4);
        s.push_data(Dir::Client, b"abc", 1, false);
        s.push_data(Dir::Server, b"SS", 2, false);
        s.push_data(Dir::Client, b"def", 3, false);
        assert_eq!(s.stored_bytes(Dir::Client), 4);
        assert_eq!(s.dropped_bytes(Dir::Client), 2);
        assert_eq!(s.data(Dir::Client), b"cdef");
        assert_eq!(s.data(Dir::Server), b"SS");
        s.push_data(Dir::Client, b"gh", 4, false);
        assert_eq!(s.data(Dir::Client), b"efgh");
        assert_eq!(s.dropped_bytes(Dir::Client), 4);
        let m: Vec<_> = s.chunks().filter_map(|c| c.marker).collect();
        assert_eq!(m, [Marker::Dropped(3), Marker::Dropped(1)]);
        let first = s.chunks().next().unwrap();
        assert_eq!(
            render_ascii(&first),
            "[3 bayt bellek sınırı nedeniyle atıldı]"
        );
    }

    #[test]
    fn renderers() {
        let data = b"Hi\x00\nthere, 0123456789!";
        let c = Chunk {
            dir: Dir::Client,
            data,
            first_pkt: 1,
            marker: None,
        };
        assert_eq!(render_ascii(&c), "Hi.\nthere, 0123456789!");
        assert_eq!(render_raw(&c)[..8], *"4869000a");
        let h = render_hex(&c);
        let lines: Vec<_> = h.lines().collect();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].starts_with("00000000  48 69 00 0a"));
        assert!(lines[0].ends_with("|Hi..there, 01234|"));
        assert!(lines[1].starts_with("00000010  35 36"));
        let gap = Chunk {
            marker: Some(Marker::Lost(7)),
            data: &[],
            ..c
        };
        assert_eq!(render_hex(&gap), "[7 bayt eksik]");
    }
}
