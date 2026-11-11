use std::fs;
use std::path::Path;

use crate::error::{CaptureError, Result};

const SYS_NET: &str = "/sys/class/net";
const IFF_UP: u32 = 0x1;

/// Ağ arayüzü bilgisi (`/sys/class/net` üzerinden).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Interface {
    pub name: String,
    pub index: u32,
    pub up: bool,
    /// `None`: MAC yok/boş (ör. tun).
    pub mac: Option<String>,
}

fn read_trim(path: &Path) -> Option<String> {
    fs::read_to_string(path).ok().map(|s| s.trim().to_owned())
}

/// Sistemdeki arayüzleri indeks sırasıyla listeler.
///
/// # Errors
/// `/sys/class/net` okunamazsa.
pub fn list_interfaces() -> Result<Vec<Interface>> {
    let dir = fs::read_dir(SYS_NET).map_err(|source| CaptureError::Io {
        op: "read_dir /sys/class/net",
        source,
    })?;
    let mut out = Vec::new();
    for entry in dir.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        let base = entry.path();
        let Some(index) = read_trim(&base.join("ifindex")).and_then(|s| s.parse().ok()) else {
            continue;
        };
        let flags = read_trim(&base.join("flags"))
            .and_then(|s| u32::from_str_radix(s.trim_start_matches("0x"), 16).ok())
            .unwrap_or(0);
        let mac = read_trim(&base.join("address")).filter(|m| !m.is_empty());
        out.push(Interface {
            name,
            index,
            up: flags & IFF_UP != 0,
            mac,
        });
    }
    out.sort_by_key(|i| i.index);
    Ok(out)
}

/// Ada göre arayüz indeksini bulur.
///
/// # Errors
/// Arayüz yoksa [`CaptureError::NoSuchInterface`].
pub fn interface_index(name: &str) -> Result<u32> {
    if name.is_empty() || name.contains('/') {
        return Err(CaptureError::NoSuchInterface(name.to_owned()));
    }
    read_trim(&Path::new(SYS_NET).join(name).join("ifindex"))
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| CaptureError::NoSuchInterface(name.to_owned()))
}
