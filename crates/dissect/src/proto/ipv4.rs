//! IPv4.

use crate::{
    Ctx, DissectResult, Dissector, Field, FieldDef, FieldType as T, FieldValue as V, Layer,
    NextHint, Reader,
};

pub struct Ipv4;

const FIELDS: &[FieldDef] = &[
    FieldDef::new("ip", T::None, "Internet Protocol Version 4"),
    FieldDef::new("ip.version", T::U8, "Version"),
    FieldDef::new("ip.hdr_len", T::U8, "Header length (bytes)"),
    FieldDef::new("ip.dsfield", T::U8, "Differentiated services field"),
    FieldDef::new("ip.dsfield.dscp", T::U8, "DSCP"),
    FieldDef::new("ip.dsfield.ecn", T::U8, "ECN"),
    FieldDef::new("ip.len", T::U16, "Total length"),
    FieldDef::new("ip.id", T::U16, "Identification"),
    FieldDef::new("ip.flags", T::U8, "Flags"),
    FieldDef::new("ip.flags.rb", T::Bool, "Reserved bit"),
    FieldDef::new("ip.flags.df", T::Bool, "Don't fragment"),
    FieldDef::new("ip.flags.mf", T::Bool, "More fragments"),
    FieldDef::new("ip.frag_offset", T::U16, "Fragment offset (bytes)"),
    FieldDef::new("ip.ttl", T::U8, "Time to live"),
    FieldDef::new("ip.proto", T::U8, "Protocol"),
    FieldDef::new("ip.checksum", T::U16, "Header checksum"),
    FieldDef::new("ip.checksum.status", T::Bool, "Header checksum correct"),
    FieldDef::new("ip.src", T::Ipv4, "Source address"),
    FieldDef::new("ip.dst", T::Ipv4, "Destination address"),
    FieldDef::alias(
        "ip.addr",
        T::Ipv4,
        "Source or destination address",
        &["ip.src", "ip.dst"],
    ),
    FieldDef::new("ip.options", T::Bytes, "Options"),
    FieldDef::new("ip.opt.type", T::U8, "Option type"),
    FieldDef::new("ip.opt.len", T::U8, "Option length"),
];

pub(crate) fn ipproto_name(p: u8) -> &'static str {
    match p {
        0 => "IPv6 Hop-by-Hop",
        1 => "ICMP",
        2 => "IGMP",
        4 => "IPIP",
        6 => "TCP",
        17 => "UDP",
        41 => "IPv6",
        43 => "IPv6 Routing",
        44 => "IPv6 Fragment",
        47 => "GRE",
        50 => "ESP",
        51 => "AH",
        58 => "ICMPv6",
        59 => "IPv6 No Next Header",
        60 => "IPv6 Destination Options",
        132 => "SCTP",
        _ => "Unknown",
    }
}

/// RFC 1071 internet checksum (tümleyen alınmamış toplam).
pub(crate) fn ones_sum(b: &[u8]) -> u16 {
    let mut s: u32 = b
        .chunks(2)
        .map(|c| {
            u32::from(u16::from_be_bytes([
                c.first().copied().unwrap_or(0),
                c.get(1).copied().unwrap_or(0),
            ]))
        })
        .sum();
    while s > 0xffff {
        s = (s & 0xffff) + (s >> 16);
    }
    u16::try_from(s).unwrap_or(u16::MAX)
}

fn option_name(t: u8) -> &'static str {
    match t {
        0 => "End of Options List",
        1 => "No-Operation",
        7 => "Record Route",
        68 => "Time Stamp",
        130 => "Security",
        131 => "Loose Source Route",
        137 => "Strict Source Route",
        148 => "Router Alert",
        _ => "Unknown",
    }
}

fn options(r: &Reader<'_>, ihl: usize) -> Field {
    let mut root = Field::new(
        "ip.options",
        format!("Options: ({} bytes)", ihl - 20),
        V::Bytes {
            offset: r.abs(20),
            len: ihl - 20,
        },
        r.abs(20),
        ihl - 20,
    );
    let mut off = 20;
    while off < ihl {
        let Some(t) = r.u8(off) else { break };
        if t <= 1 {
            root.push(Field::new(
                "ip.opt.type",
                option_name(t),
                V::U8(t),
                r.abs(off),
                1,
            ));
            off += 1;
            if t == 0 {
                break;
            }
            continue;
        }
        match r.u8(off + 1).map(usize::from) {
            Some(n) if n >= 2 && off + n <= ihl => {
                let f = Field::new(
                    "ip.opt.type",
                    format!("{} ({n} bytes)", option_name(t)),
                    V::U8(t),
                    r.abs(off),
                    n,
                )
                .with_children(vec![Field::opt(
                    "ip.opt.len",
                    "Length",
                    Some(V::U8(u8::try_from(n).unwrap_or(u8::MAX))),
                    r.abs(off + 1),
                    1,
                )]);
                root.push(f);
                off += n;
            }
            _ => {
                root.push(
                    Field::new(
                        "ip.opt.type",
                        format!("{}: bad length", option_name(t)),
                        V::U8(t),
                        r.abs(off),
                        ihl - off,
                    )
                    .malformed(),
                );
                break;
            }
        }
    }
    root
}

impl Dissector for Ipv4 {
    fn name(&self) -> &'static str {
        "ip"
    }
    fn display_name(&self) -> &'static str {
        "IPv4"
    }
    fn can_dissect(&self, _: &Ctx, hint: &NextHint, _: &[u8]) -> bool {
        matches!(hint, NextHint::EtherType(0x0800) | NextHint::IpProto(4))
    }
    fn fields(&self) -> &'static [FieldDef] {
        FIELDS
    }

    #[allow(clippy::too_many_lines)]
    fn dissect(&self, ctx: &mut Ctx, data: &[u8], base: usize) -> DissectResult {
        let r = Reader::new(data, base);
        let vihl = r.u8(0);
        let ihl = vihl.map_or(20, |b| usize::from(b & 0x0f) * 4);
        let hlen = ihl.max(20);
        let mut l = Layer::new(
            "ip",
            "Internet Protocol Version 4",
            base,
            hlen.min(data.len()),
        );

        let mut vf = Field::opt(
            "ip.version",
            "Version",
            vihl.map(|b| V::U8(b >> 4)),
            r.abs(0),
            1,
        );
        if vihl.is_some_and(|b| b >> 4 != 4) {
            vf = vf.malformed();
        }
        l.push(vf);
        let mut hf = Field::opt(
            "ip.hdr_len",
            "Header Length",
            vihl.map(|_| V::U8(u8::try_from(ihl).unwrap_or(u8::MAX))),
            r.abs(0),
            1,
        );
        if vihl.is_some() {
            hf = hf.relabel(format!("Header Length: {ihl} bytes"));
            if ihl < 20 {
                hf = hf.malformed();
            }
        }
        l.push(hf);
        let ds = r.u8(1);
        l.push(
            Field::opt(
                "ip.dsfield",
                "Differentiated Services Field",
                ds.map(V::U8),
                r.abs(1),
                1,
            )
            .with_children(
                ds.map(|d| {
                    vec![
                        Field::opt("ip.dsfield.dscp", "DSCP", Some(V::U8(d >> 2)), r.abs(1), 1),
                        Field::opt("ip.dsfield.ecn", "ECN", Some(V::U8(d & 3)), r.abs(1), 1),
                    ]
                })
                .unwrap_or_default(),
            ),
        );
        let tot = r.be_u16(2).map(usize::from);
        let mut lf = Field::opt(
            "ip.len",
            "Total Length",
            tot.map(|t| V::U16(u16::try_from(t).unwrap_or(0))),
            r.abs(2),
            2,
        );
        if tot.is_some_and(|t| t != 0 && t < hlen) {
            lf = lf.malformed();
        }
        l.push(lf);
        let id = r.be_u16(4);
        let mut idf = Field::opt("ip.id", "Identification", id.map(V::U16), r.abs(4), 2);
        if let Some(i) = id {
            idf = idf.relabel(format!("Identification: 0x{i:04x} ({i})"));
        }
        l.push(idf);
        let ff = r.be_u16(6);
        let (df, mf, frag) = ff.map_or((false, false, 0), |f| {
            (f & 0x4000 != 0, f & 0x2000 != 0, (f & 0x1fff) * 8)
        });
        let mut flags = Field::opt(
            "ip.flags",
            "Flags",
            ff.map(|f| V::U8(u8::try_from(f >> 13).unwrap_or(0))),
            r.abs(6),
            1,
        );
        if let Some(f) = ff {
            let mut names = Vec::new();
            if df {
                names.push("Don't fragment");
            }
            if mf {
                names.push("More fragments");
            }
            flags = flags
                .relabel(format!(
                    "Flags: 0x{:x}{}",
                    f >> 13,
                    if names.is_empty() {
                        String::new()
                    } else {
                        format!(", {}", names.join(", "))
                    }
                ))
                .with_children(vec![
                    Field::opt(
                        "ip.flags.rb",
                        "Reserved bit",
                        Some(V::Bool(f & 0x8000 != 0)),
                        r.abs(6),
                        1,
                    ),
                    Field::opt(
                        "ip.flags.df",
                        "Don't fragment",
                        Some(V::Bool(df)),
                        r.abs(6),
                        1,
                    ),
                    Field::opt(
                        "ip.flags.mf",
                        "More fragments",
                        Some(V::Bool(mf)),
                        r.abs(6),
                        1,
                    ),
                ]);
        }
        l.push(flags);
        l.push(Field::opt(
            "ip.frag_offset",
            "Fragment Offset",
            ff.map(|_| V::U16(frag)),
            r.abs(6),
            2,
        ));
        l.push(Field::opt(
            "ip.ttl",
            "Time to Live",
            r.u8(8).map(V::U8),
            r.abs(8),
            1,
        ));
        let proto = r.u8(9);
        let mut pf = Field::opt("ip.proto", "Protocol", proto.map(V::U8), r.abs(9), 1);
        if let Some(p) = proto {
            pf = pf.relabel(format!("Protocol: {} ({p})", ipproto_name(p)));
        }
        l.push(pf);
        let ck = r.be_u16(10);
        let mut cf = Field::opt(
            "ip.checksum",
            "Header Checksum",
            ck.map(V::U16),
            r.abs(10),
            2,
        );
        if let Some(c) = ck {
            cf = cf.relabel(format!("Header Checksum: 0x{c:04x}"));
            if let Some(h) = r.slice(0, ihl).filter(|_| ihl >= 20) {
                let good = ones_sum(h) == 0xffff;
                cf = cf.relabel(format!(
                    "Header Checksum: 0x{c:04x} [{}]",
                    if good { "correct" } else { "incorrect" }
                ));
                cf.push(Field::opt(
                    "ip.checksum.status",
                    "Checksum Status",
                    Some(V::Bool(good)),
                    r.abs(10),
                    2,
                ));
            }
        }
        l.push(cf);
        let (src, dst) = (r.ipv4(12), r.ipv4(16));
        l.push(Field::opt(
            "ip.src",
            "Source Address",
            src.map(V::Ipv4),
            r.abs(12),
            4,
        ));
        l.push(Field::opt(
            "ip.dst",
            "Destination Address",
            dst.map(V::Ipv4),
            r.abs(16),
            4,
        ));
        if ihl > 20 {
            l.push(options(&r, ihl));
        }

        if let (Some(s), Some(d)) = (src, dst) {
            l.set_label(format!("Internet Protocol Version 4, Src: {s}, Dst: {d}"));
            ctx.src = Some(s.to_string());
            ctx.dst = Some(d.to_string());
        }
        if let Some(p) = proto {
            ctx.info = Some(format!("{} ({p})", ipproto_name(p)));
        }

        // Başlık eksik/bozuksa üst katmana geçme.
        let ok = !l.is_malformed() && data.len() >= ihl;
        let (Some(tot), Some(p), true) = (tot, proto, ok) else {
            return DissectResult::new(l, NextHint::None, hlen..hlen);
        };
        // ip.len == 0: TSO/GSO ile yakalanan giden paket; kalanın tamamı yük.
        let end = if tot == 0 { data.len() } else { tot };
        ctx.l4_len = Some(end - ihl);
        if frag != 0 {
            ctx.info = Some(format!(
                "Fragmented IP protocol (proto={} {p}, off={frag})",
                ipproto_name(p)
            ));
            return DissectResult::new(l, NextHint::None, ihl..end);
        }
        DissectResult::new(l, NextHint::IpProto(p), ihl..end)
    }
}

#[cfg(test)]
mod tests {
    use crate::testutil::{dissect, sweep};
    use crate::FieldValue as V;
    use std::net::Ipv4Addr;

    pub const ICMP: &str = "0000000000000000000000000800450000241c464000400120917f0000017f00000108006668000100016162636465666768";
    /// IGMP, Router Alert seçenekli (IHL=6).
    const OPT: &str = "0000000000000000000000000800460000201c4640000102de7a0a000001e0000016940400002200f90200000000";

    #[test]
    fn header() {
        let d = dissect(ICMP);
        let ip = d.layer("ip").unwrap();
        assert_eq!(ip.offset, 14);
        assert_eq!(ip.len, 20);
        assert_eq!(
            ip.find("ip.src").unwrap().value,
            V::Ipv4(Ipv4Addr::LOCALHOST)
        );
        assert_eq!(ip.find("ip.src").unwrap().offset, 26);
        assert_eq!(ip.find("ip.ttl").unwrap().value, V::U8(64));
        assert_eq!(ip.find("ip.proto").unwrap().value, V::U8(1));
        assert_eq!(ip.find("ip.len").unwrap().value, V::U16(36));
        assert_eq!(ip.find("ip.id").unwrap().value, V::U16(0x1c46));
        assert_eq!(ip.find("ip.flags.df").unwrap().value, V::Bool(true));
        assert_eq!(ip.find("ip.flags.mf").unwrap().value, V::Bool(false));
        assert_eq!(ip.find("ip.checksum.status").unwrap().value, V::Bool(true));
        assert!(!ip.is_malformed());
    }

    #[test]
    fn bad_checksum() {
        let mut h = ICMP.to_owned();
        h.replace_range(48..52, "0000");
        let d = dissect(&h);
        assert_eq!(d.find("ip.checksum.status").unwrap().value, V::Bool(false));
    }

    #[test]
    fn options_and_unknown_proto() {
        let d = dissect(OPT);
        assert_eq!(d.protocols(), ["frame", "eth", "ip", "data"]);
        let ip = d.layer("ip").unwrap();
        assert_eq!(ip.len, 24);
        assert_eq!(ip.find("ip.hdr_len").unwrap().value, V::U8(24));
        assert_eq!(ip.find("ip.opt.type").unwrap().value, V::U8(148));
        assert_eq!(ip.find("ip.checksum.status").unwrap().value, V::Bool(true));
        assert_eq!(d.find("data.len").unwrap().value, V::U32(8));
        assert_eq!(d.summary.protocol, "IPv4");
        assert_eq!(d.summary.dst, "224.0.0.22");
    }

    #[test]
    fn bad_ihl() {
        let mut h = ICMP.to_owned();
        h.replace_range(28..30, "43");
        let d = dissect(&h);
        assert!(d.layer("ip").unwrap().is_malformed());
        assert_eq!(d.protocols(), ["frame", "eth", "ip"]);
    }

    #[test]
    fn truncation_sweep() {
        sweep(ICMP);
        sweep(OPT);
    }
}
