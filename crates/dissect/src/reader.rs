//! Sınır denetimli, panic'siz bayt okuyucu.

use std::net::{Ipv4Addr, Ipv6Addr};

/// Bir dilim üzerinde `Option` dönen big-endian okumalar. `base`, dilimin
/// frame içindeki mutlak ofsetidir.
#[derive(Debug, Clone, Copy)]
pub struct Reader<'a> {
    data: &'a [u8],
    base: usize,
}

impl<'a> Reader<'a> {
    #[must_use]
    pub fn new(data: &'a [u8], base: usize) -> Self {
        Self { data, base }
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.data.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Yerel ofseti frame'e göre mutlak ofsete çevirir.
    #[must_use]
    pub fn abs(&self, off: usize) -> usize {
        self.base.saturating_add(off)
    }

    #[must_use]
    pub fn slice(&self, off: usize, len: usize) -> Option<&'a [u8]> {
        self.data.get(off..off.checked_add(len)?)
    }

    #[must_use]
    pub fn array<const N: usize>(&self, off: usize) -> Option<[u8; N]> {
        self.slice(off, N)?.try_into().ok()
    }

    #[must_use]
    pub fn u8(&self, off: usize) -> Option<u8> {
        self.data.get(off).copied()
    }

    #[must_use]
    pub fn be_u16(&self, off: usize) -> Option<u16> {
        self.array(off).map(u16::from_be_bytes)
    }

    #[must_use]
    pub fn be_u32(&self, off: usize) -> Option<u32> {
        self.array(off).map(u32::from_be_bytes)
    }

    #[must_use]
    pub fn be_u64(&self, off: usize) -> Option<u64> {
        self.array(off).map(u64::from_be_bytes)
    }

    #[must_use]
    pub fn ipv4(&self, off: usize) -> Option<Ipv4Addr> {
        self.array::<4>(off).map(Ipv4Addr::from)
    }

    #[must_use]
    pub fn ipv6(&self, off: usize) -> Option<Ipv6Addr> {
        self.array::<16>(off).map(Ipv6Addr::from)
    }

    #[must_use]
    pub fn mac(&self, off: usize) -> Option<[u8; 6]> {
        self.array(off)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounds() {
        let r = Reader::new(&[1, 2, 3], 10);
        assert_eq!(r.be_u16(1), Some(0x0203));
        assert_eq!(r.be_u16(2), None);
        assert_eq!(r.be_u32(usize::MAX), None);
        assert_eq!(r.slice(usize::MAX, 2), None);
        assert_eq!(r.abs(2), 12);
    }
}
