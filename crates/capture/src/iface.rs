use std::ffi::{CStr, CString};
use std::ptr;

use crate::error::{CaptureError, Result};

/// Ağ arayüzü bilgisi (`getifaddrs` üzerinden; çağıran sürecin ağ ad alanına göre).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Interface {
    pub name: String,
    pub index: u32,
    pub up: bool,
    /// `None`: MAC yok/boş (ör. tun).
    pub mac: Option<String>,
    /// `IFF_LOOPBACK`.
    pub loopback: bool,
}

/// Mevcut ağ ad alanındaki arayüzleri indeks sırasıyla listeler.
///
/// `/sys/class/net` bir netns içinde (sysfs yeniden bağlanmadıysa) host'un arayüzlerini
/// gösterir; bu yüzden netlink tabanlı `getifaddrs` kullanılır. Her arayüz için bir
/// `AF_PACKET` girdisi döner (kapalı arayüzler dahil).
///
/// # Errors
/// `getifaddrs` başarısız olursa.
pub fn list_interfaces() -> Result<Vec<Interface>> {
    let mut head: *mut libc::ifaddrs = ptr::null_mut();
    // SAFETY: `head` geçerli bir çıkış işaretçisi; başarıda liste `freeifaddrs` ile serbest bırakılır.
    if unsafe { libc::getifaddrs(&raw mut head) } != 0 {
        return Err(CaptureError::Io {
            op: "getifaddrs",
            source: std::io::Error::last_os_error(),
        });
    }
    let mut out = Vec::new();
    let mut cur = head;
    while !cur.is_null() {
        // SAFETY: `cur` `getifaddrs` listesinin null olmayan bir düğümü; liste
        // `freeifaddrs`'e kadar geçerli.
        let ifa = unsafe { &*cur };
        cur = ifa.ifa_next;
        if ifa.ifa_addr.is_null() || ifa.ifa_name.is_null() {
            continue;
        }
        // SAFETY: `ifa_addr` null değil ve en az `sockaddr` boyunda.
        let family = i32::from(unsafe { (*ifa.ifa_addr).sa_family });
        if family != libc::AF_PACKET {
            continue;
        }
        // SAFETY: AF_PACKET girdilerinde `ifa_addr` bir `sockaddr_ll`'yi gösterir.
        let ll = unsafe { &*ifa.ifa_addr.cast::<libc::sockaddr_ll>() };
        // SAFETY: `ifa_name` null değil, NUL ile biten bir C dizgesi.
        let name = unsafe { CStr::from_ptr(ifa.ifa_name) }
            .to_string_lossy()
            .into_owned();
        let halen = usize::from(ll.sll_halen).min(ll.sll_addr.len());
        let addr = &ll.sll_addr[..halen];
        let mac = (!addr.is_empty()).then(|| {
            addr.iter()
                .map(|b| format!("{b:02x}"))
                .collect::<Vec<_>>()
                .join(":")
        });
        let flags = ifa.ifa_flags;
        out.push(Interface {
            name,
            index: u32::try_from(ll.sll_ifindex).unwrap_or(0),
            up: flags & libc::IFF_UP as u32 != 0,
            mac,
            loopback: flags & libc::IFF_LOOPBACK as u32 != 0,
        });
    }
    // SAFETY: `head` yukarıdaki başarılı `getifaddrs` çağrısından; bir kez serbest bırakılır.
    unsafe { libc::freeifaddrs(head) };
    out.sort_by_key(|i| i.index);
    Ok(out)
}

/// Ada göre arayüz indeksini bulur (mevcut netns'te).
///
/// # Errors
/// Arayüz yoksa [`CaptureError::NoSuchInterface`].
pub fn interface_index(name: &str) -> Result<u32> {
    let no = || CaptureError::NoSuchInterface(name.to_owned());
    if name.is_empty() || name.contains('/') {
        return Err(no());
    }
    let c = CString::new(name).map_err(|_| no())?;
    // SAFETY: `c` geçerli, NUL ile biten bir C dizgesi.
    match unsafe { libc::if_nametoindex(c.as_ptr()) } {
        0 => Err(no()),
        i => Ok(i),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `getifaddrs` yetki istemez; netns'te bile en az `lo` vardır.
    #[test]
    fn lists_interfaces_sorted_with_loopback() {
        let l = list_interfaces().unwrap();
        assert!(l.windows(2).all(|w| w[0].index <= w[1].index));
        let lo = l.iter().find(|i| i.loopback).expect("loopback yok");
        assert_eq!(interface_index(&lo.name).unwrap(), lo.index);
        for i in &l {
            if let Some(m) = &i.mac {
                assert!(m.split(':').all(|b| b.len() == 2), "{m}");
            }
        }
    }

    #[test]
    fn bad_interface_names() {
        for n in ["", "a/b", "nul\0x", "pakizyok0"] {
            assert!(
                matches!(interface_index(n), Err(CaptureError::NoSuchInterface(_))),
                "{n}"
            );
        }
    }
}
