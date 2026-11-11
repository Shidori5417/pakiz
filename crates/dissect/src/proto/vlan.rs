//! IEEE 802.1Q / 802.1ad (`QinQ`) VLAN etiketi.

use super::eth::ethertype_name;
use crate::{
    Ctx, DissectResult, Dissector, Field, FieldDef, FieldType as T, FieldValue as V, Layer,
    NextHint, Reader,
};

pub struct Vlan;

const FIELDS: &[FieldDef] = &[
    FieldDef::new("vlan", T::None, "802.1Q Virtual LAN"),
    FieldDef::new("vlan.priority", T::U8, "Priority (PCP)"),
    FieldDef::new("vlan.dei", T::Bool, "Drop eligible indicator"),
    FieldDef::new("vlan.id", T::U16, "VLAN ID"),
    FieldDef::new("vlan.etype", T::U16, "Type"),
];

impl Dissector for Vlan {
    fn name(&self) -> &'static str {
        "vlan"
    }
    fn display_name(&self) -> &'static str {
        "802.1Q"
    }
    fn can_dissect(&self, _: &Ctx, hint: &NextHint, _: &[u8]) -> bool {
        matches!(hint, NextHint::EtherType(0x8100 | 0x88a8 | 0x9100))
    }
    fn fields(&self) -> &'static [FieldDef] {
        FIELDS
    }

    fn dissect(&self, ctx: &mut Ctx, data: &[u8], base: usize) -> DissectResult {
        let r = Reader::new(data, base);
        let hdr = 4.min(data.len());
        let mut l = Layer::new("vlan", "802.1Q Virtual LAN", base, hdr);
        let tci = r.be_u16(0);
        l.push(Field::opt(
            "vlan.priority",
            "Priority",
            tci.map(|t| V::U8(u8::try_from(t >> 13).unwrap_or_default())),
            r.abs(0),
            2,
        ));
        l.push(Field::opt(
            "vlan.dei",
            "DEI",
            tci.map(|t| V::Bool(t & 0x1000 != 0)),
            r.abs(0),
            2,
        ));
        l.push(Field::opt(
            "vlan.id",
            "ID",
            tci.map(|t| V::U16(t & 0x0fff)),
            r.abs(0),
            2,
        ));
        let ty = r.be_u16(2);
        let mut tf = Field::opt("vlan.etype", "Type", ty.map(V::U16), r.abs(2), 2);
        if let Some(t) = ty {
            tf = tf.relabel(format!("Type: {} (0x{t:04x})", ethertype_name(t)));
        }
        l.push(tf);
        if let Some(t) = tci {
            let (pri, id) = (t >> 13, t & 0x0fff);
            l.set_label(format!("802.1Q Virtual LAN, PRI: {pri}, ID: {id}"));
            ctx.info = Some(format!("VLAN {id}"));
        }
        let next = match ty {
            Some(t) if t >= 0x0600 => NextHint::EtherType(t),
            _ => NextHint::None,
        };
        DissectResult::new(l, next, hdr..data.len())
    }
}

#[cfg(test)]
mod tests {
    use crate::testutil::{dissect, sweep};
    use crate::FieldValue as V;

    /// 802.1ad S-tag 100 → 802.1Q C-tag 200 (PCP 3) → IPv4/UDP.
    const QINQ: &str = "02000000000202000000000188a80064810060c80800450000201c464000401108830a0101010a01010214e914e9000c000001020304";

    #[test]
    fn qinq() {
        let d = dissect(QINQ);
        assert_eq!(
            d.protocols(),
            ["frame", "eth", "vlan", "vlan", "ip", "udp", "data"]
        );
        assert_eq!(d.layers[2].find("vlan.id").unwrap().value, V::U16(100));
        assert_eq!(
            d.layers[2].find("vlan.etype").unwrap().value,
            V::U16(0x8100)
        );
        assert_eq!(d.layers[3].find("vlan.id").unwrap().value, V::U16(200));
        assert_eq!(d.layers[3].find("vlan.priority").unwrap().value, V::U8(3));
        assert_eq!(d.layers[3].offset, 18);
        assert_eq!(d.summary.src, "10.1.1.1");
    }

    #[test]
    fn truncation_sweep() {
        sweep(QINQ);
    }
}
