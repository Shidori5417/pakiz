//! TCP.

use std::fmt::Write as _;

use crate::{
    Ctx, DissectResult, Dissector, Field, FieldDef, FieldType as T, FieldValue as V, Layer,
    NextHint, Reader,
};

pub struct Tcp;

const FIELDS: &[FieldDef] = &[
    FieldDef::new("tcp", T::None, "Transmission Control Protocol"),
    FieldDef::new("tcp.srcport", T::U16, "Source port"),
    FieldDef::new("tcp.dstport", T::U16, "Destination port"),
    FieldDef::alias(
        "tcp.port",
        T::U16,
        "Source or destination port",
        &["tcp.srcport", "tcp.dstport"],
    ),
    FieldDef::new("tcp.seq", T::U32, "Sequence number (raw)"),
    FieldDef::new("tcp.ack", T::U32, "Acknowledgment number (raw)"),
    FieldDef::new("tcp.hdr_len", T::U8, "Header length (bytes)"),
    FieldDef::new("tcp.flags", T::U16, "Flags"),
    FieldDef::new("tcp.flags.res", T::U8, "Reserved"),
    FieldDef::new("tcp.flags.cwr", T::Bool, "Congestion Window Reduced"),
    FieldDef::new("tcp.flags.ece", T::Bool, "ECN-Echo"),
    FieldDef::new("tcp.flags.urg", T::Bool, "Urgent"),
    FieldDef::new("tcp.flags.ack", T::Bool, "Acknowledgment"),
    FieldDef::new("tcp.flags.push", T::Bool, "Push"),
    FieldDef::new("tcp.flags.reset", T::Bool, "Reset"),
    FieldDef::alias(
        "tcp.flags.psh",
        T::Bool,
        "Push (alias)",
        &["tcp.flags.push"],
    ),
    FieldDef::alias(
        "tcp.flags.rst",
        T::Bool,
        "Reset (alias)",
        &["tcp.flags.reset"],
    ),
    FieldDef::new("tcp.flags.syn", T::Bool, "Syn"),
    FieldDef::new("tcp.flags.fin", T::Bool, "Fin"),
    FieldDef::new("tcp.window_size", T::U16, "Window (unscaled)"),
    FieldDef::new("tcp.checksum", T::U16, "Checksum"),
    FieldDef::new("tcp.urgent_pointer", T::U16, "Urgent pointer"),
    FieldDef::new("tcp.len", T::U32, "Segment payload length"),
    FieldDef::new("tcp.options", T::Bytes, "Options"),
    FieldDef::new("tcp.option_kind", T::U8, "Option kind"),
    FieldDef::new("tcp.option_len", T::U8, "Option length"),
    FieldDef::new("tcp.options.nop", T::None, "No-Operation"),
    FieldDef::new("tcp.options.eol", T::None, "End of Option List"),
    FieldDef::new("tcp.options.mss", T::None, "Maximum segment size option"),
    FieldDef::new("tcp.options.mss_val", T::U16, "MSS value"),
    FieldDef::new("tcp.options.wscale", T::None, "Window scale option"),
    FieldDef::new(
        "tcp.options.wscale.shift",
        T::U8,
        "Window scale shift count",
    ),
    FieldDef::new("tcp.options.sack_perm", T::None, "SACK permitted option"),
    FieldDef::new("tcp.options.sack", T::None, "SACK option"),
    FieldDef::new("tcp.options.sack_le", T::U32, "SACK left edge"),
    FieldDef::new("tcp.options.sack_re", T::U32, "SACK right edge"),
    FieldDef::new("tcp.options.timestamp", T::None, "Timestamps option"),
    FieldDef::new("tcp.options.timestamp.tsval", T::U32, "Timestamp value"),
    FieldDef::new(
        "tcp.options.timestamp.tsecr",
        T::U32,
        "Timestamp echo reply",
    ),
    FieldDef::new("tcp.options.unknown", T::None, "Unknown option"),
];

/// (bit, filtre adı, kısa ad, uzun ad) — yüksek bitten düşüğe.
const FLAGS: [(u16, &str, &str, &str); 8] = [
    (0x80, "tcp.flags.cwr", "CWR", "Congestion Window Reduced"),
    (0x40, "tcp.flags.ece", "ECE", "ECN-Echo"),
    (0x20, "tcp.flags.urg", "URG", "Urgent"),
    (0x10, "tcp.flags.ack", "ACK", "Acknowledgment"),
    (0x08, "tcp.flags.push", "PSH", "Push"),
    (0x04, "tcp.flags.reset", "RST", "Reset"),
    (0x02, "tcp.flags.syn", "SYN", "Syn"),
    (0x01, "tcp.flags.fin", "FIN", "Fin"),
];

/// Seçenekleri ayrıştırır; özet satırına eklenecek metni döner.
fn options(r: &Reader<'_>, thl: usize) -> (Field, String) {
    let mut root = Field::new(
        "tcp.options",
        format!("Options: ({} bytes)", thl - 20),
        V::Bytes {
            offset: r.abs(20),
            len: thl - 20,
        },
        r.abs(20),
        thl - 20,
    );
    let mut info = String::new();
    let mut off = 20;
    while off < thl {
        let Some(kind) = r.u8(off) else { break };
        let kf = Field::opt("tcp.option_kind", "Kind", Some(V::U8(kind)), r.abs(off), 1);
        if kind <= 1 {
            let (name, label) = if kind == 0 {
                ("tcp.options.eol", "End of Option List (EOL)")
            } else {
                ("tcp.options.nop", "No-Operation (NOP)")
            };
            root.push(Field::new(name, label, V::None, r.abs(off), 1).with_children(vec![kf]));
            off += 1;
            if kind == 0 {
                break;
            }
            continue;
        }
        let n = r.u8(off + 1).map_or(0, usize::from);
        let want_ok = match kind {
            2 => n == 4,
            3 => n == 3,
            4 => n == 2,
            5 => n >= 10 && (n - 2).is_multiple_of(8),
            8 => n == 10,
            _ => n >= 2,
        };
        if !want_ok || off + n > thl {
            root.push(
                Field::new(
                    "tcp.options.unknown",
                    format!("Option kind {kind}: bad length {n}"),
                    V::None,
                    r.abs(off),
                    thl - off,
                )
                .with_children(vec![kf])
                .malformed(),
            );
            break;
        }
        let lf = Field::opt(
            "tcp.option_len",
            "Length",
            Some(V::U8(u8::try_from(n).unwrap_or(u8::MAX))),
            r.abs(off + 1),
            1,
        );
        let mut kids = vec![kf, lf];
        let (name, label) = match kind {
            2 => {
                let v = r.be_u16(off + 2).unwrap_or(0);
                kids.push(Field::opt(
                    "tcp.options.mss_val",
                    "MSS Value",
                    Some(V::U16(v)),
                    r.abs(off + 2),
                    2,
                ));
                let _ = write!(info, " MSS={v}");
                (
                    "tcp.options.mss",
                    format!("Maximum segment size: {v} bytes"),
                )
            }
            3 => {
                let s = r.u8(off + 2).unwrap_or(0);
                kids.push(Field::opt(
                    "tcp.options.wscale.shift",
                    "Shift count",
                    Some(V::U8(s)),
                    r.abs(off + 2),
                    1,
                ));
                let mul = 1u32.checked_shl(u32::from(s.min(14))).unwrap_or(0);
                let _ = write!(info, " WS={mul}");
                (
                    "tcp.options.wscale",
                    format!("Window scale: {s} (multiply by {mul})"),
                )
            }
            4 => {
                info.push_str(" SACK_PERM");
                ("tcp.options.sack_perm", "SACK permitted".to_owned())
            }
            5 => {
                let mut o = off + 2;
                while o + 8 <= off + n {
                    kids.push(Field::opt(
                        "tcp.options.sack_le",
                        "left edge",
                        r.be_u32(o).map(V::U32),
                        r.abs(o),
                        4,
                    ));
                    kids.push(Field::opt(
                        "tcp.options.sack_re",
                        "right edge",
                        r.be_u32(o + 4).map(V::U32),
                        r.abs(o + 4),
                        4,
                    ));
                    o += 8;
                }
                ("tcp.options.sack", format!("SACK ({} blocks)", (n - 2) / 8))
            }
            8 => {
                let (v, e) = (
                    r.be_u32(off + 2).unwrap_or(0),
                    r.be_u32(off + 6).unwrap_or(0),
                );
                kids.push(Field::opt(
                    "tcp.options.timestamp.tsval",
                    "Timestamp value",
                    Some(V::U32(v)),
                    r.abs(off + 2),
                    4,
                ));
                kids.push(Field::opt(
                    "tcp.options.timestamp.tsecr",
                    "Timestamp echo reply",
                    Some(V::U32(e)),
                    r.abs(off + 6),
                    4,
                ));
                let _ = write!(info, " TSval={v} TSecr={e}");
                (
                    "tcp.options.timestamp",
                    format!("Timestamps: TSval {v}, TSecr {e}"),
                )
            }
            _ => (
                "tcp.options.unknown",
                format!("Unknown option (kind {kind})"),
            ),
        };
        root.push(Field::new(name, label, V::None, r.abs(off), n).with_children(kids));
        off += n;
    }
    (root, info)
}

impl Dissector for Tcp {
    fn name(&self) -> &'static str {
        "tcp"
    }
    fn display_name(&self) -> &'static str {
        "TCP"
    }
    fn can_dissect(&self, _: &Ctx, hint: &NextHint, _: &[u8]) -> bool {
        *hint == NextHint::IpProto(6)
    }
    fn fields(&self) -> &'static [FieldDef] {
        FIELDS
    }

    fn dissect(&self, ctx: &mut Ctx, data: &[u8], base: usize) -> DissectResult {
        let r = Reader::new(data, base);
        let off_byte = r.u8(12);
        let thl = off_byte.map_or(20, |b| usize::from(b >> 4) * 4);
        let hlen = thl.max(20);
        let mut l = Layer::new(
            "tcp",
            "Transmission Control Protocol",
            base,
            hlen.min(data.len()),
        );
        let (sp, dp) = (r.be_u16(0), r.be_u16(2));
        l.push(Field::opt(
            "tcp.srcport",
            "Source Port",
            sp.map(V::U16),
            r.abs(0),
            2,
        ));
        l.push(Field::opt(
            "tcp.dstport",
            "Destination Port",
            dp.map(V::U16),
            r.abs(2),
            2,
        ));
        let (seq, ack) = (r.be_u32(4), r.be_u32(8));
        l.push(Field::opt(
            "tcp.seq",
            "Sequence Number (raw)",
            seq.map(V::U32),
            r.abs(4),
            4,
        ));
        l.push(Field::opt(
            "tcp.ack",
            "Acknowledgment Number (raw)",
            ack.map(V::U32),
            r.abs(8),
            4,
        ));
        let mut hf = Field::opt(
            "tcp.hdr_len",
            "Header Length",
            off_byte.map(|_| V::U8(u8::try_from(thl).unwrap_or(u8::MAX))),
            r.abs(12),
            1,
        );
        if off_byte.is_some() {
            hf = hf.relabel(format!("Header Length: {thl} bytes"));
            if thl < 20 {
                hf = hf.malformed();
            }
        }
        l.push(hf);
        let fl = r.be_u16(12).map(|v| v & 0x0fff);
        let set: Vec<&str> = fl
            .map(|f| {
                FLAGS
                    .iter()
                    .rev()
                    .filter(|x| f & x.0 != 0)
                    .map(|x| x.2)
                    .collect()
            })
            .unwrap_or_default();
        let mut ff = Field::opt("tcp.flags", "Flags", fl.map(V::U16), r.abs(12), 2);
        if let Some(f) = fl {
            let mut kids = vec![Field::opt(
                "tcp.flags.res",
                "Reserved",
                Some(V::U8(u8::try_from(f >> 9).unwrap_or(0))),
                r.abs(12),
                1,
            )];
            kids.extend(FLAGS.iter().map(|&(bit, name, _, long)| {
                Field::opt(name, long, Some(V::Bool(f & bit != 0)), r.abs(13), 1)
            }));
            ff = ff
                .relabel(format!("Flags: 0x{f:03x} ({})", set.join(", ")))
                .with_children(kids);
        }
        l.push(ff);
        let win = r.be_u16(14);
        l.push(Field::opt(
            "tcp.window_size",
            "Window",
            win.map(V::U16),
            r.abs(14),
            2,
        ));
        let ck = r.be_u16(16);
        let mut cf = Field::opt("tcp.checksum", "Checksum", ck.map(V::U16), r.abs(16), 2);
        if let Some(v) = ck {
            cf = cf.relabel(format!("Checksum: 0x{v:04x} [unverified]"));
        }
        l.push(cf);
        l.push(Field::opt(
            "tcp.urgent_pointer",
            "Urgent Pointer",
            r.be_u16(18).map(V::U16),
            r.abs(18),
            2,
        ));

        let header_ok = !l.is_malformed() && data.len() >= thl;
        let mut opt_info = String::new();
        if header_ok && thl > 20 {
            let (f, i) = options(&r, thl);
            l.push(f);
            opt_info = i;
        }
        let seg_len = ctx.l4_len.unwrap_or(data.len()).saturating_sub(thl);
        if header_ok {
            l.push(Field::opt(
                "tcp.len",
                "TCP Segment Len",
                Some(V::U32(u32::try_from(seg_len).unwrap_or(u32::MAX))),
                r.abs(12),
                0,
            ));
        }

        if let (Some(sp), Some(dp)) = (sp, dp) {
            l.set_label(format!(
                "Transmission Control Protocol, Src Port: {sp}, Dst Port: {dp}"
            ));
            let mut info = format!("{sp} → {dp}");
            if header_ok {
                let _ = write!(info, " [{}] Seq={}", set.join(", "), seq.unwrap_or(0));
                if fl.is_some_and(|f| f & 0x10 != 0) {
                    let _ = write!(info, " Ack={}", ack.unwrap_or(0));
                }
                let _ = write!(info, " Win={} Len={seg_len}{opt_info}", win.unwrap_or(0));
            }
            ctx.info = Some(info);
        }
        match (header_ok, sp, dp) {
            (true, Some(src), Some(dst)) => {
                DissectResult::new(l, NextHint::TcpPort { src, dst }, thl..data.len())
            }
            _ => DissectResult::new(l, NextHint::None, hlen..hlen),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::testutil::{dissect, sweep};
    use crate::FieldValue as V;

    // 10.0.0.1:443 → 10.0.0.2:51234 SYN-ACK, MSS/SACK_PERM/TS/NOP/WS.
    const SYNACK: &str = "02000000000202000000000108004500003c1c46400040060a740a0000010a00000201bbc8220000000000000001a012ffff00000000020405b40402080a000000010000000201030307";

    #[test]
    fn syn_ack() {
        let d = dissect(SYNACK);
        assert_eq!(d.protocols(), ["frame", "eth", "ip", "tcp"]);
        assert_eq!(
            d.summary.info,
            "443 → 51234 [SYN, ACK] Seq=0 Ack=1 Win=65535 Len=0 MSS=1460 SACK_PERM TSval=1 TSecr=2 WS=128"
        );
        assert_eq!(d.summary.protocol, "TCP");
        let t = d.layer("tcp").unwrap();
        assert_eq!(t.offset, 34);
        assert_eq!(t.len, 40);
        assert_eq!(t.find("tcp.srcport").unwrap().value, V::U16(443));
        assert_eq!(t.find("tcp.dstport").unwrap().value, V::U16(51234));
        assert_eq!(t.find("tcp.ack").unwrap().value, V::U32(1));
        assert_eq!(t.find("tcp.len").unwrap().value, V::U32(0));
        assert_eq!(t.find("tcp.window_size").unwrap().value, V::U16(65535));
        assert_eq!(t.find("tcp.flags").unwrap().value, V::U16(0x012));
        assert_eq!(t.find("tcp.flags.syn").unwrap().value, V::Bool(true));
        assert_eq!(t.find("tcp.flags.ack").unwrap().value, V::Bool(true));
        assert_eq!(t.find("tcp.flags.fin").unwrap().value, V::Bool(false));
        assert_eq!(t.find("tcp.options.mss_val").unwrap().value, V::U16(1460));
        assert_eq!(t.find("tcp.options.wscale.shift").unwrap().value, V::U8(7));
        assert_eq!(
            t.find("tcp.options.timestamp.tsecr").unwrap().value,
            V::U32(2)
        );
        assert!(t.find("tcp.options.sack_perm").is_some());
        assert!(t.find("tcp.options.nop").is_some());
        assert!(!t.is_malformed());
    }

    #[test]
    fn payload_and_sack() {
        // ACK+PSH, SACK (1 blok) + 2xNOP, 3 bayt yük.
        let h = "020000000002020000000001 0800 \
                 450000370000400040060000 0a000001 0a000002 \
                 c822 01bb 00000064 000000c8 8018 0100 0000 0000 \
                 0101 050a 000003e8 000007d0 \
                 616263";
        let d = dissect(h);
        assert_eq!(d.protocols(), ["frame", "eth", "ip", "tcp", "data"]);
        assert_eq!(d.find("tcp.len").unwrap().value, V::U32(3));
        assert_eq!(d.find("tcp.options.sack_le").unwrap().value, V::U32(1000));
        assert_eq!(d.find("tcp.options.sack_re").unwrap().value, V::U32(2000));
        assert_eq!(
            d.summary.info,
            "51234 → 443 [PSH, ACK] Seq=100 Ack=200 Win=256 Len=3"
        );
    }

    #[test]
    fn bad_option_length() {
        let mut h = SYNACK.to_owned();
        // MSS uzunluğunu 4 → 9 yap.
        h.replace_range(110..112, "09");
        let d = dissect(&h);
        assert!(d.layer("tcp").unwrap().is_malformed());
    }

    #[test]
    fn truncation_sweep() {
        sweep(SYNACK);
    }
}
