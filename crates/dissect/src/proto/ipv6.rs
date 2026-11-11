//! IPv6 ve uzantı başlıkları (Hop-by-Hop, Routing, Fragment, Destination Options, AH).

use super::ipv4::ipproto_name;
use crate::{
    Ctx, DissectResult, Dissector, Field, FieldDef, FieldType as T, FieldValue as V, Layer,
    NextHint, Reader,
};

pub struct Ipv6;

const FIELDS: &[FieldDef] = &[
    FieldDef::new("ipv6", T::None, "Internet Protocol Version 6"),
    FieldDef::new("ipv6.version", T::U8, "Version"),
    FieldDef::new("ipv6.tclass", T::U8, "Traffic class"),
    FieldDef::new("ipv6.flow", T::U32, "Flow label"),
    FieldDef::new("ipv6.plen", T::U16, "Payload length"),
    FieldDef::new("ipv6.nxt", T::U8, "Next header"),
    FieldDef::new("ipv6.hlim", T::U8, "Hop limit"),
    FieldDef::new("ipv6.src", T::Ipv6, "Source address"),
    FieldDef::new("ipv6.dst", T::Ipv6, "Destination address"),
    FieldDef::alias(
        "ipv6.addr",
        T::Ipv6,
        "Source or destination address",
        &["ipv6.src", "ipv6.dst"],
    ),
    FieldDef::new("ipv6.hopopts", T::Bytes, "Hop-by-Hop Options"),
    FieldDef::new("ipv6.hopopts.nxt", T::U8, "Next header"),
    FieldDef::new("ipv6.hopopts.len", T::U8, "Length"),
    FieldDef::new("ipv6.routing", T::Bytes, "Routing header"),
    FieldDef::new("ipv6.routing.nxt", T::U8, "Next header"),
    FieldDef::new("ipv6.routing.len", T::U8, "Length"),
    FieldDef::new("ipv6.routing.type", T::U8, "Routing type"),
    FieldDef::new("ipv6.routing.segleft", T::U8, "Segments left"),
    FieldDef::new("ipv6.dstopts", T::Bytes, "Destination Options"),
    FieldDef::new("ipv6.dstopts.nxt", T::U8, "Next header"),
    FieldDef::new("ipv6.dstopts.len", T::U8, "Length"),
    FieldDef::new("ipv6.fragment", T::Bytes, "Fragment header"),
    FieldDef::new("ipv6.fragment.nxt", T::U8, "Next header"),
    FieldDef::new("ipv6.fragment.offset", T::U16, "Fragment offset (bytes)"),
    FieldDef::new("ipv6.fragment.more", T::Bool, "More fragments"),
    FieldDef::new("ipv6.fragment.id", T::U32, "Identification"),
    FieldDef::new("ah", T::Bytes, "Authentication Header (skipped)"),
    FieldDef::new("ah.nxt", T::U8, "Next header"),
];

/// Uzantı başlığı türüne göre alan adları.
struct Ext {
    root: &'static str,
    nxt: &'static str,
    len: Option<&'static str>,
    title: &'static str,
}

fn ext(nxt: u8) -> Option<Ext> {
    let e = |root, nxt, len, title| {
        Some(Ext {
            root,
            nxt,
            len,
            title,
        })
    };
    match nxt {
        0 => e(
            "ipv6.hopopts",
            "ipv6.hopopts.nxt",
            Some("ipv6.hopopts.len"),
            "Hop-by-Hop Options",
        ),
        43 => e(
            "ipv6.routing",
            "ipv6.routing.nxt",
            Some("ipv6.routing.len"),
            "Routing Header",
        ),
        44 => e(
            "ipv6.fragment",
            "ipv6.fragment.nxt",
            None,
            "Fragment Header",
        ),
        51 => e("ah", "ah.nxt", None, "Authentication Header"),
        60 => e(
            "ipv6.dstopts",
            "ipv6.dstopts.nxt",
            Some("ipv6.dstopts.len"),
            "Destination Options",
        ),
        _ => None,
    }
}

const MAX_EXT: usize = 8;

impl Dissector for Ipv6 {
    fn name(&self) -> &'static str {
        "ipv6"
    }
    fn display_name(&self) -> &'static str {
        "IPv6"
    }
    fn can_dissect(&self, _: &Ctx, hint: &NextHint, _: &[u8]) -> bool {
        matches!(hint, NextHint::EtherType(0x86dd) | NextHint::IpProto(41))
    }
    fn fields(&self) -> &'static [FieldDef] {
        FIELDS
    }

    #[allow(clippy::too_many_lines)]
    fn dissect(&self, ctx: &mut Ctx, data: &[u8], base: usize) -> DissectResult {
        let r = Reader::new(data, base);
        let mut l = Layer::new(
            "ipv6",
            "Internet Protocol Version 6",
            base,
            40.min(data.len()),
        );
        let w = r.be_u32(0);
        let mut vf = Field::opt(
            "ipv6.version",
            "Version",
            w.map(|w| V::U8(u8::try_from(w >> 28).unwrap_or(0))),
            r.abs(0),
            1,
        );
        if w.is_some_and(|w| w >> 28 != 6) {
            vf = vf.malformed();
        }
        l.push(vf);
        l.push(Field::opt(
            "ipv6.tclass",
            "Traffic Class",
            w.map(|w| V::U8(u8::try_from((w >> 20) & 0xff).unwrap_or(0))),
            r.abs(0),
            2,
        ));
        l.push(Field::opt(
            "ipv6.flow",
            "Flow Label",
            w.map(|w| V::U32(w & 0x000f_ffff)),
            r.abs(1),
            3,
        ));
        let plen = r.be_u16(4).map(usize::from);
        l.push(Field::opt(
            "ipv6.plen",
            "Payload Length",
            r.be_u16(4).map(V::U16),
            r.abs(4),
            2,
        ));
        let first_nxt = r.u8(6);
        let mut nf = Field::opt("ipv6.nxt", "Next Header", first_nxt.map(V::U8), r.abs(6), 1);
        if let Some(n) = first_nxt {
            nf = nf.relabel(format!("Next Header: {} ({n})", ipproto_name(n)));
        }
        l.push(nf);
        l.push(Field::opt(
            "ipv6.hlim",
            "Hop Limit",
            r.u8(7).map(V::U8),
            r.abs(7),
            1,
        ));
        let (src, dst) = (r.ipv6(8), r.ipv6(24));
        l.push(Field::opt(
            "ipv6.src",
            "Source Address",
            src.map(V::Ipv6),
            r.abs(8),
            16,
        ));
        l.push(Field::opt(
            "ipv6.dst",
            "Destination Address",
            dst.map(V::Ipv6),
            r.abs(24),
            16,
        ));
        if let (Some(s), Some(d)) = (src, dst) {
            l.set_label(format!("Internet Protocol Version 6, Src: {s}, Dst: {d}"));
            ctx.src = Some(s.to_string());
            ctx.dst = Some(d.to_string());
        }
        if let Some(n) = first_nxt {
            ctx.info = Some(format!("IPv6 {} ({n})", ipproto_name(n)));
        }
        let (Some(plen), Some(mut nxt), false) =
            (plen, first_nxt, l.is_malformed() || data.len() < 40)
        else {
            return DissectResult::new(l, NextHint::None, 40..40);
        };
        // plen == 0: jumbogram veya TSO; kalanın tamamı yük.
        let end = if plen == 0 { data.len() } else { 40 + plen };
        let mut off = 40;
        let mut later_fragment = false;
        let mut bad = false;
        for _ in 0..MAX_EXT {
            let Some(e) = ext(nxt) else { break };
            let (n, hl) = (r.u8(off), r.u8(off + 1));
            let size = match (nxt, hl) {
                (51, Some(h)) => (usize::from(h) + 2) * 4,
                (_, Some(h)) => (usize::from(h) + 1) * 8,
                (44, _) | (_, None) => 8,
            };
            let mut f = Field::new(
                e.root,
                format!("{} ({size} bytes)", e.title),
                V::Bytes {
                    offset: r.abs(off),
                    len: size,
                },
                r.abs(off),
                size,
            );
            f.push(Field::opt(
                e.nxt,
                "Next Header",
                n.map(V::U8),
                r.abs(off),
                1,
            ));
            if let Some(name) = e.len {
                f.push(Field::opt(name, "Length", hl.map(V::U8), r.abs(off + 1), 1));
            }
            if nxt == 43 {
                f.push(Field::opt(
                    "ipv6.routing.type",
                    "Type",
                    r.u8(off + 2).map(V::U8),
                    r.abs(off + 2),
                    1,
                ));
                f.push(Field::opt(
                    "ipv6.routing.segleft",
                    "Segments Left",
                    r.u8(off + 3).map(V::U8),
                    r.abs(off + 3),
                    1,
                ));
            }
            if nxt == 44 {
                let fo = r.be_u16(off + 2);
                f.push(Field::opt(
                    "ipv6.fragment.offset",
                    "Offset",
                    fo.map(|v| V::U16(v & 0xfff8)),
                    r.abs(off + 2),
                    2,
                ));
                f.push(Field::opt(
                    "ipv6.fragment.more",
                    "More Fragments",
                    fo.map(|v| V::Bool(v & 1 != 0)),
                    r.abs(off + 2),
                    2,
                ));
                f.push(Field::opt(
                    "ipv6.fragment.id",
                    "Identification",
                    r.be_u32(off + 4).map(V::U32),
                    r.abs(off + 4),
                    4,
                ));
                later_fragment = fo.is_some_and(|v| v & 0xfff8 != 0);
            }
            let short = r.slice(off, size).is_none() || off + size > end;
            if short {
                f = f.malformed();
            }
            l.push(f);
            match n {
                Some(n) if !short => nxt = n,
                _ => {
                    bad = true;
                    break;
                }
            }
            off += size;
        }
        l.len = off.min(data.len());
        if bad {
            return DissectResult::new(l, NextHint::None, off..off);
        }
        ctx.l4_len = Some(end.saturating_sub(off));
        ctx.info = Some(format!("IPv6 {} ({nxt})", ipproto_name(nxt)));
        if later_fragment {
            ctx.info = Some(format!("IPv6 fragment (nxt={} ({nxt}))", ipproto_name(nxt)));
            return DissectResult::new(l, NextHint::None, off..end);
        }
        let next = if nxt == 59 {
            NextHint::None
        } else {
            NextHint::IpProto(nxt)
        };
        DissectResult::new(l, next, off..end)
    }
}

#[cfg(test)]
mod tests {
    use crate::testutil::{dissect, sweep};
    use crate::FieldValue as V;

    pub const ECHO: &str = "02000000000202000000000186dd6000000000120040fe800000000000000000000000000001fe8000000000000000000000000000023a0001040000000080000000123400016869";
    const FRAG: &str = "02000000000202000000000186dd6000000000102c4020010db800000000000000000000000120010db8000000000000000000000002110005c8deadbeef4142434445464748";

    #[test]
    fn hop_by_hop() {
        let d = dissect(ECHO);
        assert_eq!(d.protocols(), ["frame", "eth", "ipv6", "icmpv6", "data"]);
        let ip = d.layer("ipv6").unwrap();
        assert_eq!(ip.len, 48);
        assert_eq!(ip.find("ipv6.nxt").unwrap().value, V::U8(0));
        assert_eq!(ip.find("ipv6.hopopts.nxt").unwrap().value, V::U8(58));
        assert_eq!(ip.find("ipv6.hlim").unwrap().value, V::U8(64));
        assert_eq!(
            ip.find("ipv6.src").unwrap().value,
            V::Ipv6("fe80::1".parse().unwrap())
        );
        assert_eq!(ip.find("ipv6.dst").unwrap().offset, 38);
        assert_eq!(d.summary.src, "fe80::1");
        assert_eq!(d.summary.dst, "fe80::2");
    }

    #[test]
    fn non_first_fragment() {
        let d = dissect(FRAG);
        assert_eq!(d.protocols(), ["frame", "eth", "ipv6", "data"]);
        assert_eq!(d.find("ipv6.fragment.offset").unwrap().value, V::U16(1480));
        assert_eq!(
            d.find("ipv6.fragment.id").unwrap().value,
            V::U32(0xdead_beef)
        );
        assert_eq!(d.find("data.len").unwrap().value, V::U32(8));
    }

    #[test]
    fn truncation_sweep() {
        sweep(ECHO);
        sweep(FRAG);
    }
}
