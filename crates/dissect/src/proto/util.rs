//! Uygulama katmanı dissector'larının ortak yardımcıları.

use std::fmt::Write as _;

use crate::{Field, FieldValue as V, NextHint};

/// UDP ipucunda kaynak veya hedef port `ports` içinde mi?
pub(crate) fn udp_port(hint: &NextHint, ports: &[u16]) -> bool {
    matches!(*hint, NextHint::UdpPort { src, dst } if ports.contains(&src) || ports.contains(&dst))
}

/// TCP ipucunda kaynak veya hedef port `ports` içinde mi?
pub(crate) fn tcp_port(hint: &NextHint, ports: &[u16]) -> bool {
    matches!(*hint, NextHint::TcpPort { src, dst } if ports.contains(&src) || ports.contains(&dst))
}

pub(crate) fn is_tcp(hint: &NextHint) -> bool {
    matches!(hint, NextHint::TcpPort { .. })
}

/// Baytları kayıpsız-olmayan UTF-8 metne çevirir.
pub(crate) fn lossy(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

/// Bitişik küçük harf onaltılık.
pub(crate) fn hex(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        let _ = write!(s, "{x:02x}");
    }
    s
}

/// Metin alanı.
pub(crate) fn str_field(
    name: &'static str,
    title: &str,
    s: Option<String>,
    off: usize,
    len: usize,
) -> Field {
    Field::opt(name, title, s.map(|s| V::Str(s.into())), off, len)
}

/// Ham bayt alanı; etikette onaltılık değer (uzunsa kısaltılmış).
pub(crate) fn bytes_field(
    name: &'static str,
    title: &str,
    b: Option<&[u8]>,
    off: usize,
    len: usize,
) -> Field {
    let f = Field::opt(
        name,
        title,
        b.map(|b| V::Bytes {
            offset: off,
            len: b.len(),
        }),
        off,
        len,
    );
    match b {
        Some(b) if b.len() <= 32 => f.relabel(format!("{title}: {}", hex(b))),
        Some(b) => f.relabel(format!("{title}: {}… ({} bytes)", hex(&b[..32]), b.len())),
        None => f,
    }
}

/// `data` içinde `pat`'in ilk konumu.
pub(crate) fn find(data: &[u8], pat: &[u8]) -> Option<usize> {
    if pat.is_empty() {
        return Some(0);
    }
    data.windows(pat.len()).position(|w| w == pat)
}

/// Saniye cinsinden UNIX zamanını `Nov 11, 2026 12:34:56.123456789 UTC` biçimine çevirir.
pub(crate) fn fmt_utc(secs: i64, nanos: u32) -> String {
    const MON: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let days = secs.div_euclid(86_400);
    let sod = secs.rem_euclid(86_400);
    // Howard Hinnant, civil_from_days.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    let mon = usize::try_from(m - 1)
        .ok()
        .and_then(|i| MON.get(i))
        .unwrap_or(&"???");
    format!(
        "{mon} {d:02}, {y} {:02}:{:02}:{:02}.{nanos:09} UTC",
        sod / 3600,
        sod % 3600 / 60,
        sod % 60
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn utc() {
        assert_eq!(fmt_utc(0, 0), "Jan 01, 1970 00:00:00.000000000 UTC");
        assert_eq!(
            fmt_utc(1_709_251_200, 5),
            "Mar 01, 2024 00:00:00.000000005 UTC"
        );
        assert_eq!(
            fmt_utc(-2_208_988_800, 0),
            "Jan 01, 1900 00:00:00.000000000 UTC"
        );
    }

    #[test]
    fn find_pat() {
        assert_eq!(find(b"abc\r\n\r\nx", b"\r\n\r\n"), Some(3));
        assert_eq!(find(b"ab", b"abc"), None);
    }
}
