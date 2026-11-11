//! UDP.

use crate::{
    Ctx, DissectResult, Dissector, Field, FieldDef, FieldType as T, FieldValue as V, Layer,
    NextHint, Reader,
};

pub struct Udp;

const FIELDS: &[FieldDef] = &[
    FieldDef::new("udp", T::None, "User Datagram Protocol"),
    FieldDef::new("udp.srcport", T::U16, "Source port"),
    FieldDef::new("udp.dstport", T::U16, "Destination port"),
    FieldDef::alias(
        "udp.port",
        T::U16,
        "Source or destination port",
        &["udp.srcport", "udp.dstport"],
    ),
    FieldDef::new("udp.length", T::U16, "Length"),
    FieldDef::new("udp.checksum", T::U16, "Checksum"),
];

impl Dissector for Udp {
    fn name(&self) -> &'static str {
        "udp"
    }
    fn display_name(&self) -> &'static str {
        "UDP"
    }
    fn can_dissect(&self, _: &Ctx, hint: &NextHint, _: &[u8]) -> bool {
        *hint == NextHint::IpProto(17)
    }
    fn fields(&self) -> &'static [FieldDef] {
        FIELDS
    }

    fn dissect(&self, ctx: &mut Ctx, data: &[u8], base: usize) -> DissectResult {
        let r = Reader::new(data, base);
        let hdr = 8.min(data.len());
        let mut l = Layer::new("udp", "User Datagram Protocol", base, hdr);
        let (sp, dp, len) = (r.be_u16(0), r.be_u16(2), r.be_u16(4));
        l.push(Field::opt(
            "udp.srcport",
            "Source Port",
            sp.map(V::U16),
            r.abs(0),
            2,
        ));
        l.push(Field::opt(
            "udp.dstport",
            "Destination Port",
            dp.map(V::U16),
            r.abs(2),
            2,
        ));
        let mut lf = Field::opt("udp.length", "Length", len.map(V::U16), r.abs(4), 2);
        if len.is_some_and(|n| n < 8) {
            lf = lf.malformed();
        }
        l.push(lf);
        let ck = r.be_u16(6);
        let mut cf = Field::opt("udp.checksum", "Checksum", ck.map(V::U16), r.abs(6), 2);
        if let Some(v) = ck {
            cf = cf.relabel(format!("Checksum: 0x{v:04x} [unverified]"));
        }
        l.push(cf);
        let (Some(src), Some(dst), Some(n), false) =
            (sp, dp, len.map(usize::from), l.is_malformed())
        else {
            return DissectResult::last(l);
        };
        l.set_label(format!(
            "User Datagram Protocol, Src Port: {src}, Dst Port: {dst}"
        ));
        ctx.info = Some(format!("{src} → {dst} Len={}", n - 8));
        DissectResult::new(l, NextHint::UdpPort { src, dst }, 8..n)
    }
}

#[cfg(test)]
mod tests {
    use crate::testutil::{dissect, sweep};
    use crate::FieldValue as V;

    /// mDNS 192.168.1.10:5353 → 224.0.0.251:5353, 4 bayt yük.
    const MDNS: &str = "01005e0000fb0200000000010800450000201c464000ff11bcd8c0a8010ae00000fb14e914e9000c000001020304";

    #[test]
    fn udp() {
        let d = dissect(MDNS);
        assert_eq!(d.protocols(), ["frame", "eth", "ip", "udp", "data"]);
        assert_eq!(d.summary.info, "5353 → 5353 Len=4");
        assert_eq!(d.summary.protocol, "UDP");
        assert_eq!(d.summary.dst, "224.0.0.251");
        assert_eq!(d.find("udp.length").unwrap().value, V::U16(12));
        assert_eq!(d.find("udp.dstport").unwrap().offset, 36);
        assert_eq!(d.find("data.len").unwrap().value, V::U32(4));
    }

    #[test]
    fn ethernet_padding_not_data() {
        // 60 bayta doldurulmuş çerçeve: padding UDP yüküne karışmamalı.
        let d = dissect(&format!("{MDNS}{}", "00".repeat(14)));
        assert_eq!(d.find("data.len").unwrap().value, V::U32(4));
    }

    #[test]
    fn truncation_sweep() {
        sweep(MDNS);
    }
}
