//! Ethernet II.

use crate::{
    fmt_mac, Ctx, DissectResult, Dissector, Field, FieldDef, FieldType as T, FieldValue as V,
    Layer, NextHint, Reader,
};

pub struct Ethernet;

const FIELDS: &[FieldDef] = &[
    FieldDef::new("eth", T::None, "Ethernet II"),
    FieldDef::new("eth.dst", T::Mac, "Destination"),
    FieldDef::new("eth.src", T::Mac, "Source"),
    FieldDef::alias(
        "eth.addr",
        T::Mac,
        "Source or Destination",
        &["eth.src", "eth.dst"],
    ),
    FieldDef::new("eth.type", T::U16, "Type"),
    FieldDef::new("eth.len", T::U16, "Length (802.3)"),
];

pub(crate) fn ethertype_name(t: u16) -> &'static str {
    match t {
        0x0800 => "IPv4",
        0x0806 => "ARP",
        0x86dd => "IPv6",
        0x8100 => "802.1Q Virtual LAN",
        0x88a8 => "802.1ad",
        0x88cc => "LLDP",
        0x8847 => "MPLS",
        0x888e => "802.1X",
        _ => "Unknown",
    }
}

impl Dissector for Ethernet {
    fn name(&self) -> &'static str {
        "eth"
    }
    fn display_name(&self) -> &'static str {
        "ETH"
    }
    fn can_dissect(&self, _: &Ctx, hint: &NextHint, _: &[u8]) -> bool {
        *hint == NextHint::Named("eth")
    }
    fn fields(&self) -> &'static [FieldDef] {
        FIELDS
    }

    fn dissect(&self, ctx: &mut Ctx, data: &[u8], base: usize) -> DissectResult {
        let r = Reader::new(data, base);
        let hdr = 14.min(data.len());
        let mut l = Layer::new("eth", "Ethernet II", base, hdr);
        let (dst, src, ty) = (r.mac(0), r.mac(6), r.be_u16(12));
        l.push(Field::opt(
            "eth.dst",
            "Destination",
            dst.map(V::Mac),
            r.abs(0),
            6,
        ));
        l.push(Field::opt(
            "eth.src",
            "Source",
            src.map(V::Mac),
            r.abs(6),
            6,
        ));
        let next = match ty {
            Some(t) if t >= 0x0600 => {
                l.push(
                    Field::opt("eth.type", "Type", Some(V::U16(t)), r.abs(12), 2)
                        .relabel(format!("Type: {} (0x{t:04x})", ethertype_name(t))),
                );
                ctx.info = Some(format!("Ethertype 0x{t:04x}"));
                NextHint::EtherType(t)
            }
            Some(n) => {
                l.push(Field::opt(
                    "eth.len",
                    "Length",
                    Some(V::U16(n)),
                    r.abs(12),
                    2,
                ));
                ctx.info = Some(format!("IEEE 802.3, length {n}"));
                NextHint::None
            }
            None => {
                l.push(Field::opt("eth.type", "Type", None, r.abs(12), 2));
                NextHint::None
            }
        };
        if let (Some(s), Some(d)) = (src, dst) {
            let (s, d) = (fmt_mac(&s), fmt_mac(&d));
            l.set_label(format!("Ethernet II, Src: {s}, Dst: {d}"));
            ctx.src = Some(s);
            ctx.dst = Some(d);
        }
        DissectResult::new(l, next, hdr..data.len())
    }
}

#[cfg(test)]
mod tests {
    use crate::testutil::{dissect, sweep};
    use crate::FieldValue as V;

    const ICMP: &str = "0000000000000000000000000800450000241c464000400120917f0000017f00000108006668000100016162636465666768";

    #[test]
    fn ethernet() {
        let d = dissect("02000000000202000000000188cc0102");
        let e = d.layer("eth").unwrap();
        assert_eq!(e.find("eth.src").unwrap().value, V::Mac([2, 0, 0, 0, 0, 1]));
        assert_eq!(e.find("eth.dst").unwrap().value, V::Mac([2, 0, 0, 0, 0, 2]));
        assert_eq!(e.find("eth.type").unwrap().value, V::U16(0x88cc));
        assert_eq!(e.find("eth.type").unwrap().offset, 12);
        assert_eq!(d.protocols(), ["frame", "eth", "data"]);
        assert_eq!(d.summary.src, "02:00:00:00:00:01");
        assert_eq!(d.find("data.len").unwrap().value, V::U32(2));
        assert_eq!(d.find("data.data").unwrap().offset, 14);
    }

    #[test]
    fn truncation_sweep() {
        sweep(ICMP);
        sweep("02000000000202000000000100100102");
    }
}
