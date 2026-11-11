//! ARP (Ethernet/IPv4 adresleri ayrıntılı, diğerleri ham bayt).

use crate::{
    fmt_mac, Ctx, DissectResult, Dissector, Field, FieldDef, FieldType as T, FieldValue as V,
    Layer, NextHint, Reader,
};

pub struct Arp;

const FIELDS: &[FieldDef] = &[
    FieldDef::new("arp", T::None, "Address Resolution Protocol"),
    FieldDef::new("arp.hw.type", T::U16, "Hardware type"),
    FieldDef::new("arp.proto.type", T::U16, "Protocol type"),
    FieldDef::new("arp.hw.size", T::U8, "Hardware size"),
    FieldDef::new("arp.proto.size", T::U8, "Protocol size"),
    FieldDef::new("arp.opcode", T::U16, "Opcode"),
    FieldDef::new("arp.src.hw_mac", T::Mac, "Sender MAC address"),
    FieldDef::new("arp.src.proto_ipv4", T::Ipv4, "Sender IP address"),
    FieldDef::new("arp.dst.hw_mac", T::Mac, "Target MAC address"),
    FieldDef::new("arp.dst.proto_ipv4", T::Ipv4, "Target IP address"),
    FieldDef::new("arp.src.hw", T::Bytes, "Sender hardware address"),
    FieldDef::new("arp.src.proto", T::Bytes, "Sender protocol address"),
    FieldDef::new("arp.dst.hw", T::Bytes, "Target hardware address"),
    FieldDef::new("arp.dst.proto", T::Bytes, "Target protocol address"),
];

fn opcode_name(op: u16) -> &'static str {
    match op {
        1 => "request",
        2 => "reply",
        3 => "reverse request",
        4 => "reverse reply",
        _ => "unknown",
    }
}

impl Dissector for Arp {
    fn name(&self) -> &'static str {
        "arp"
    }
    fn display_name(&self) -> &'static str {
        "ARP"
    }
    fn can_dissect(&self, _: &Ctx, hint: &NextHint, _: &[u8]) -> bool {
        *hint == NextHint::EtherType(0x0806)
    }
    fn fields(&self) -> &'static [FieldDef] {
        FIELDS
    }

    fn dissect(&self, ctx: &mut Ctx, data: &[u8], base: usize) -> DissectResult {
        let r = Reader::new(data, base);
        let (hl, pl) = (r.u8(4), r.u8(5));
        let total = match (hl, pl) {
            (Some(h), Some(p)) => 8 + 2 * (usize::from(h) + usize::from(p)),
            _ => 8,
        };
        let mut l = Layer::new(
            "arp",
            "Address Resolution Protocol",
            base,
            total.min(data.len()),
        );
        l.push(Field::opt(
            "arp.hw.type",
            "Hardware type",
            r.be_u16(0).map(V::U16),
            r.abs(0),
            2,
        ));
        l.push(Field::opt(
            "arp.proto.type",
            "Protocol type",
            r.be_u16(2).map(V::U16),
            r.abs(2),
            2,
        ));
        l.push(Field::opt(
            "arp.hw.size",
            "Hardware size",
            hl.map(V::U8),
            r.abs(4),
            1,
        ));
        l.push(Field::opt(
            "arp.proto.size",
            "Protocol size",
            pl.map(V::U8),
            r.abs(5),
            1,
        ));
        let op = r.be_u16(6);
        let mut of = Field::opt("arp.opcode", "Opcode", op.map(V::U16), r.abs(6), 2);
        if let Some(o) = op {
            of = of.relabel(format!("Opcode: {} ({o})", opcode_name(o)));
            l.set_label(format!("Address Resolution Protocol ({})", opcode_name(o)));
        }
        l.push(of);

        let (Some(hl), Some(pl)) = (hl.map(usize::from), pl.map(usize::from)) else {
            return DissectResult::last(l);
        };
        let (sha, spa, tha, tpa) = (8, 8 + hl, 8 + hl + pl, 8 + 2 * hl + pl);
        if hl == 6 && pl == 4 {
            let (sm, si, tm, ti) = (r.mac(sha), r.ipv4(spa), r.mac(tha), r.ipv4(tpa));
            l.push(Field::opt(
                "arp.src.hw_mac",
                "Sender MAC address",
                sm.map(V::Mac),
                r.abs(sha),
                6,
            ));
            l.push(Field::opt(
                "arp.src.proto_ipv4",
                "Sender IP address",
                si.map(V::Ipv4),
                r.abs(spa),
                4,
            ));
            l.push(Field::opt(
                "arp.dst.hw_mac",
                "Target MAC address",
                tm.map(V::Mac),
                r.abs(tha),
                6,
            ));
            l.push(Field::opt(
                "arp.dst.proto_ipv4",
                "Target IP address",
                ti.map(V::Ipv4),
                r.abs(tpa),
                4,
            ));
            ctx.info = Some(match (op, sm, si, ti) {
                (Some(1), _, Some(s), Some(t)) if s == t => {
                    format!("Gratuitous ARP for {s} (Request)")
                }
                (Some(1), _, Some(s), Some(t)) => format!("Who has {t}? Tell {s}"),
                (Some(2), Some(m), Some(s), _) => format!("{s} is at {}", fmt_mac(&m)),
                (Some(o), ..) => format!("ARP {}", opcode_name(o)),
                _ => "ARP".to_owned(),
            });
        } else {
            let bytes = |name, title, off: usize, n: usize| {
                let v = r.slice(off, n).map(|_| V::Bytes {
                    offset: r.abs(off),
                    len: n,
                });
                Field::opt(name, title, v, r.abs(off), n)
            };
            l.push(bytes("arp.src.hw", "Sender hardware address", sha, hl));
            l.push(bytes("arp.src.proto", "Sender protocol address", spa, pl));
            l.push(bytes("arp.dst.hw", "Target hardware address", tha, hl));
            l.push(bytes("arp.dst.proto", "Target protocol address", tpa, pl));
            ctx.info = Some(format!("ARP {}", op.map_or("?", opcode_name)));
        }
        DissectResult::last(l)
    }
}

#[cfg(test)]
mod tests {
    use crate::testutil::{dissect, sweep};
    use crate::FieldValue as V;
    use std::net::Ipv4Addr;

    // 60 bayt (padding dahil) gerçek ARP isteği.
    const REQ: &str = "ffffffffffff000c29aabbcc08060001080006040001000c29aabbcc0a0000020000000000000a000001000000000000000000000000000000";
    const REPLY: &str = "000c29aabbcc 000c29112233 0806 0001 0800 06 04 0002 000c29112233 0a000001 000c29aabbcc 0a000002";

    #[test]
    fn request() {
        let d = dissect(REQ);
        assert_eq!(d.protocols(), ["frame", "eth", "arp"]);
        assert_eq!(d.summary.info, "Who has 10.0.0.1? Tell 10.0.0.2");
        assert_eq!(d.summary.protocol, "ARP");
        assert_eq!(d.find("arp.opcode").unwrap().value, V::U16(1));
        let spa = d.find("arp.src.proto_ipv4").unwrap();
        assert_eq!(spa.value, V::Ipv4(Ipv4Addr::new(10, 0, 0, 2)));
        assert_eq!(spa.offset, 28);
        assert!(!d.layers[2].is_malformed());
    }

    #[test]
    fn reply() {
        let d = dissect(REPLY);
        assert_eq!(d.summary.info, "10.0.0.1 is at 00:0c:29:11:22:33");
    }

    #[test]
    fn truncation_sweep() {
        sweep(REQ);
        sweep(REPLY);
        let d = dissect(&REQ[..2 * 30]);
        assert!(d.layers[2].is_malformed());
    }
}
