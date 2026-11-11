//! NTP v3/v4 (UDP 123), RFC 5905.

use std::net::Ipv4Addr;
use std::time::{Duration, UNIX_EPOCH};

use super::util::{fmt_utc, udp_port};
use crate::{
    Ctx, DissectResult, Dissector, Field, FieldDef, FieldType as T, FieldValue as V, Layer,
    NextHint, Reader,
};

pub struct Ntp;

/// 1900-01-01 ile 1970-01-01 arası saniye.
const NTP_UNIX_DELTA: i64 = 2_208_988_800;

const FIELDS: &[FieldDef] = &[
    FieldDef::new("ntp", T::None, "Network Time Protocol"),
    FieldDef::new("ntp.flags", T::U8, "Flags"),
    FieldDef::new("ntp.flags.li", T::U8, "Leap indicator"),
    FieldDef::new("ntp.flags.vn", T::U8, "Version number"),
    FieldDef::new("ntp.flags.mode", T::U8, "Mode"),
    FieldDef::new("ntp.stratum", T::U8, "Peer clock stratum"),
    FieldDef::new("ntp.ppoll", T::U8, "Peer polling interval (log2 s)"),
    FieldDef::new(
        "ntp.precision",
        T::U8,
        "Peer clock precision (log2 s, signed)",
    ),
    FieldDef::new("ntp.rootdelay", T::U32, "Root delay (16.16 s)"),
    FieldDef::new("ntp.rootdispersion", T::U32, "Root dispersion (16.16 s)"),
    FieldDef::new("ntp.refid", T::Bytes, "Reference ID"),
    FieldDef::new("ntp.reftime", T::Time, "Reference timestamp"),
    FieldDef::new("ntp.org", T::Time, "Origin timestamp"),
    FieldDef::new("ntp.rec", T::Time, "Receive timestamp"),
    FieldDef::new("ntp.xmt", T::Time, "Transmit timestamp"),
];

fn mode_name(m: u8) -> &'static str {
    match m {
        1 => "symmetric active",
        2 => "symmetric passive",
        3 => "client",
        4 => "server",
        5 => "broadcast",
        6 => "reserved for NTP control message",
        7 => "reserved for private use",
        _ => "reserved",
    }
}

fn li_name(li: u8) -> &'static str {
    match li {
        0 => "no warning",
        1 => "last minute of the day has 61 seconds",
        2 => "last minute of the day has 59 seconds",
        _ => "unknown (clock unsynchronized)",
    }
}

/// 64 bit NTP zaman damgası alanı.
fn timestamp(r: &Reader<'_>, off: usize, name: &'static str, title: &str) -> Field {
    let Some(raw) = r.be_u64(off) else {
        return Field::opt(name, title, None, r.abs(off), 8);
    };
    let secs = i64::from(u32::try_from(raw >> 32).unwrap_or(0)) - NTP_UNIX_DELTA;
    let frac = raw & 0xffff_ffff;
    let nanos = u32::try_from((frac * 1_000_000_000) >> 32).unwrap_or(0);
    let t = if secs >= 0 {
        UNIX_EPOCH.checked_add(Duration::new(secs.unsigned_abs(), nanos))
    } else {
        UNIX_EPOCH
            .checked_sub(Duration::from_secs(secs.unsigned_abs()))
            .and_then(|t| t.checked_add(Duration::from_nanos(u64::from(nanos))))
    };
    let label = if raw == 0 {
        format!("{title}: (0)NULL")
    } else {
        format!("{title}: {}", fmt_utc(secs, nanos))
    };
    match t {
        Some(t) => Field::new(name, label, V::Time(t), r.abs(off), 8),
        None => Field::opt(name, title, None, r.abs(off), 8),
    }
}

/// 16.16 sabit noktalı saniye → metin.
fn short_secs(v: u32) -> String {
    format!("{:.6} seconds", f64::from(v) / 65536.0)
}

impl Dissector for Ntp {
    fn name(&self) -> &'static str {
        "ntp"
    }
    fn display_name(&self) -> &'static str {
        "NTP"
    }
    fn can_dissect(&self, _: &Ctx, hint: &NextHint, data: &[u8]) -> bool {
        udp_port(hint, &[123]) && !data.is_empty()
    }
    fn fields(&self) -> &'static [FieldDef] {
        FIELDS
    }

    fn dissect(&self, ctx: &mut Ctx, data: &[u8], base: usize) -> DissectResult {
        let r = Reader::new(data, base);
        let mut l = Layer::new("ntp", "Network Time Protocol", base, data.len().min(48));
        let fl = r.u8(0).unwrap_or(0);
        let (li, vn, mode) = (fl >> 6, (fl >> 3) & 7, fl & 7);
        let mut ff = Field::new(
            "ntp.flags",
            format!(
                "Flags: 0x{fl:02x}, Leap Indicator: {}, Version number: NTP Version {vn}, Mode: {}",
                li_name(li),
                mode_name(mode)
            ),
            V::U8(fl),
            base,
            1,
        );
        ff.push(Field::new(
            "ntp.flags.li",
            format!("Leap Indicator: {} ({li})", li_name(li)),
            V::U8(li),
            base,
            1,
        ));
        ff.push(Field::new(
            "ntp.flags.vn",
            format!("Version number: NTP Version {vn} ({vn})"),
            V::U8(vn),
            base,
            1,
        ));
        ff.push(Field::new(
            "ntp.flags.mode",
            format!("Mode: {} ({mode})", mode_name(mode)),
            V::U8(mode),
            base,
            1,
        ));
        l.push(ff);
        ctx.info = Some(format!("NTP Version {vn}, {}", mode_name(mode)));
        l.set_label(format!(
            "Network Time Protocol (NTP Version {vn}, {})",
            mode_name(mode)
        ));
        if mode == 6 || mode == 7 {
            // Kontrol/özel iletiler farklı biçimde; yalnızca bayraklar.
            return DissectResult::last(l);
        }
        let stratum = r.u8(1);
        let mut sf = Field::opt(
            "ntp.stratum",
            "Peer Clock Stratum",
            stratum.map(V::U8),
            r.abs(1),
            1,
        );
        if let Some(s) = stratum {
            let d = match s {
                0 => "unspecified or invalid".to_owned(),
                1 => "primary reference".to_owned(),
                2..=15 => "secondary reference".to_owned(),
                _ => "reserved".to_owned(),
            };
            sf = sf.relabel(format!("Peer Clock Stratum: {d} ({s})"));
        }
        l.push(sf);
        let poll = r.u8(2);
        let mut pf = Field::opt(
            "ntp.ppoll",
            "Peer Polling Interval",
            poll.map(V::U8),
            r.abs(2),
            1,
        );
        if let Some(p) = poll {
            pf = pf.relabel(format!(
                "Peer Polling Interval: {p} ({} seconds)",
                1u64.checked_shl(u32::from(p)).unwrap_or(0)
            ));
        }
        l.push(pf);
        let prec = r.u8(3);
        let mut prf = Field::opt(
            "ntp.precision",
            "Peer Clock Precision",
            prec.map(V::U8),
            r.abs(3),
            1,
        );
        if let Some(p) = prec {
            let e = i32::from(i8::from_ne_bytes([p]));
            prf = prf.relabel(format!(
                "Peer Clock Precision: {:.9} seconds ({e})",
                2f64.powi(e)
            ));
        }
        l.push(prf);
        for (o, name, title) in [
            (4, "ntp.rootdelay", "Root Delay"),
            (8, "ntp.rootdispersion", "Root Dispersion"),
        ] {
            let v = r.be_u32(o);
            let mut f = Field::opt(name, title, v.map(V::U32), r.abs(o), 4);
            if let Some(v) = v {
                f = f.relabel(format!("{title}: {}", short_secs(v)));
            }
            l.push(f);
        }
        let refid = r.array::<4>(12);
        let mut rf = Field::opt(
            "ntp.refid",
            "Reference ID",
            refid.map(|_| V::Bytes {
                offset: r.abs(12),
                len: 4,
            }),
            r.abs(12),
            4,
        );
        if let Some(b) = refid {
            let txt = if stratum.is_some_and(|s| s <= 1) {
                let s: String = b
                    .iter()
                    .take_while(|&&c| c != 0)
                    .map(|&c| char::from(c))
                    .collect();
                if s.chars().all(|c| c.is_ascii_graphic()) {
                    s
                } else {
                    format!("{b:02x?}")
                }
            } else {
                Ipv4Addr::from(b).to_string()
            };
            rf = rf.relabel(format!("Reference ID: {txt}"));
        }
        l.push(rf);
        l.push(timestamp(&r, 16, "ntp.reftime", "Reference Timestamp"));
        l.push(timestamp(&r, 24, "ntp.org", "Origin Timestamp"));
        l.push(timestamp(&r, 32, "ntp.rec", "Receive Timestamp"));
        l.push(timestamp(&r, 40, "ntp.xmt", "Transmit Timestamp"));
        DissectResult::last(l)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::time::{Duration, UNIX_EPOCH};

    use crate::testutil::{dissect, sweep};
    use crate::FieldValue as V;

    // 192.168.1.10:123 → 162.159.200.1:123, NTPv4 istemci isteği (yalnız xmt dolu).
    pub(crate) const CLIENT: &str = "a0b1c2d3e4f53c22fb1a2b3c08004500004c1c4640004011f207c0a8010aa29fc801007b007b0038aca723000000000000000000000000000000000000000000000000000000000000000000000000000000e98b990080000000";
    // Sunucu cevabı, stratum 3, refid 10.0.0.1.
    pub(crate) const SERVER: &str = "a0b1c2d3e4f53c22fb1a2b3c08004500004c1c4640004011f207a29fc801c0a8010a007b007b0038712f240306ec00000a3d00001b5c0a000001e98b951880000000e98b990080000000e98b990080100000e98b990080200000";

    #[test]
    fn client_request() {
        let d = dissect(CLIENT);
        assert_eq!(d.protocols(), ["frame", "eth", "ip", "udp", "ntp"]);
        assert_eq!(d.summary.protocol, "NTP");
        assert_eq!(d.summary.info, "NTP Version 4, client");
        assert_eq!(d.find("ntp.flags.mode").unwrap().value, V::U8(3));
        assert_eq!(d.find("ntp.flags.vn").unwrap().value, V::U8(4));
        assert_eq!(d.find("ntp.stratum").unwrap().value, V::U8(0));
        let x = d.find("ntp.xmt").unwrap();
        // 2024-03-01T00:00:00.5Z
        assert_eq!(
            x.value,
            V::Time(UNIX_EPOCH + Duration::from_millis(1_709_251_200_500))
        );
        assert!(
            x.label.contains("Mar 01, 2024 00:00:00.500000000 UTC"),
            "{}",
            x.label
        );
        assert!(d.find("ntp.org").unwrap().label.contains("NULL"));
        assert!(!d.layer("ntp").unwrap().is_malformed());
    }

    #[test]
    fn server_reply() {
        let d = dissect(SERVER);
        assert_eq!(d.summary.info, "NTP Version 4, server");
        assert_eq!(d.find("ntp.stratum").unwrap().value, V::U8(3));
        assert_eq!(d.find("ntp.refid").unwrap().label, "Reference ID: 10.0.0.1");
        assert!(d.find("ntp.precision").unwrap().label.ends_with("(-20)"));
    }

    #[test]
    fn truncation_sweep() {
        sweep(CLIENT);
        sweep(SERVER);
    }
}
