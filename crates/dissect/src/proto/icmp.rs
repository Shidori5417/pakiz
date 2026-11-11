//! ICMP (IPv4).

use crate::{
    Ctx, DissectResult, Dissector, Field, FieldDef, FieldType as T, FieldValue as V, Layer,
    NextHint, Reader,
};

pub struct Icmp;

const FIELDS: &[FieldDef] = &[
    FieldDef::new("icmp", T::None, "Internet Control Message Protocol"),
    FieldDef::new("icmp.type", T::U8, "Type"),
    FieldDef::new("icmp.code", T::U8, "Code"),
    FieldDef::new("icmp.checksum", T::U16, "Checksum"),
    FieldDef::new("icmp.ident", T::U16, "Identifier"),
    FieldDef::new("icmp.seq", T::U16, "Sequence number"),
];

fn type_name(t: u8, c: u8) -> String {
    let unreach = |c| match c {
        0 => "Network unreachable",
        1 => "Host unreachable",
        2 => "Protocol unreachable",
        3 => "Port unreachable",
        4 => "Fragmentation needed",
        13 => "Communication administratively filtered",
        _ => "Unknown code",
    };
    match t {
        0 => "Echo (ping) reply".into(),
        3 => format!("Destination unreachable ({})", unreach(c)),
        5 => "Redirect".into(),
        8 => "Echo (ping) request".into(),
        9 => "Router advertisement".into(),
        10 => "Router solicitation".into(),
        11 => format!(
            "Time-to-live exceeded{}",
            if c == 1 {
                " (Fragment reassembly time exceeded)"
            } else {
                " (Time to live exceeded in transit)"
            }
        ),
        12 => "Parameter problem".into(),
        13 => "Timestamp request".into(),
        14 => "Timestamp reply".into(),
        _ => format!("Type {t}"),
    }
}

impl Dissector for Icmp {
    fn name(&self) -> &'static str {
        "icmp"
    }
    fn display_name(&self) -> &'static str {
        "ICMP"
    }
    fn can_dissect(&self, _: &Ctx, hint: &NextHint, _: &[u8]) -> bool {
        *hint == NextHint::IpProto(1)
    }
    fn fields(&self) -> &'static [FieldDef] {
        FIELDS
    }

    fn dissect(&self, ctx: &mut Ctx, data: &[u8], base: usize) -> DissectResult {
        let r = Reader::new(data, base);
        let hdr = 8.min(data.len());
        let mut l = Layer::new("icmp", "Internet Control Message Protocol", base, hdr);
        let (t, c) = (r.u8(0), r.u8(1));
        let mut tf = Field::opt("icmp.type", "Type", t.map(V::U8), r.abs(0), 1);
        if let Some(t) = t {
            tf = tf.relabel(format!("Type: {t} ({})", type_name(t, c.unwrap_or(0))));
        }
        l.push(tf);
        l.push(Field::opt("icmp.code", "Code", c.map(V::U8), r.abs(1), 1));
        let ck = r.be_u16(2);
        let mut cf = Field::opt("icmp.checksum", "Checksum", ck.map(V::U16), r.abs(2), 2);
        if let Some(v) = ck {
            cf = cf.relabel(format!("Checksum: 0x{v:04x}"));
        }
        l.push(cf);
        let Some(t) = t else {
            return DissectResult::last(l);
        };
        let mut info = type_name(t, c.unwrap_or(0));
        if matches!(t, 0 | 8 | 13 | 14) {
            let (id, seq) = (r.be_u16(4), r.be_u16(6));
            let mut idf = Field::opt("icmp.ident", "Identifier", id.map(V::U16), r.abs(4), 2);
            if let Some(i) = id {
                idf = idf.relabel(format!("Identifier: {i} (0x{i:04x})"));
            }
            l.push(idf);
            l.push(Field::opt(
                "icmp.seq",
                "Sequence Number",
                seq.map(V::U16),
                r.abs(6),
                2,
            ));
            if let (Some(i), Some(s)) = (id, seq) {
                info = format!("{info} id=0x{i:04x}, seq={s}");
            }
        }
        l.set_label(format!("Internet Control Message Protocol, {info}"));
        ctx.info = Some(info);
        DissectResult::new(l, NextHint::None, hdr..data.len())
    }
}

#[cfg(test)]
mod tests {
    use crate::testutil::{dissect, sweep};
    use crate::FieldValue as V;

    const ECHO_REQ: &str = "0000000000000000000000000800450000241c464000400120917f0000017f00000108006668000100016162636465666768";
    /// Port unreachable (gövdede orijinal IP başlığı + 8 bayt).
    const UNREACH: &str = "000000000000000000000000080045c000381c46000040014a5d7f0000017f0000010303fcfc00000000450000201c46400040113c7b7f0000017f0000010035d431000c0000";

    #[test]
    fn echo_request() {
        let d = dissect(ECHO_REQ);
        assert_eq!(d.protocols(), ["frame", "eth", "ip", "icmp", "data"]);
        assert_eq!(d.summary.info, "Echo (ping) request id=0x0001, seq=1");
        assert_eq!(d.summary.protocol, "ICMP");
        assert_eq!(d.find("icmp.type").unwrap().value, V::U8(8));
        assert_eq!(d.find("icmp.seq").unwrap().offset, 40);
        assert_eq!(d.find("data.len").unwrap().value, V::U32(8));
    }

    #[test]
    fn unreachable() {
        let d = dissect(UNREACH);
        assert_eq!(d.summary.info, "Destination unreachable (Port unreachable)");
        assert_eq!(d.find("icmp.code").unwrap().value, V::U8(3));
        assert!(d.find("icmp.ident").is_none());
    }

    #[test]
    fn truncation_sweep() {
        sweep(ECHO_REQ);
        sweep(UNREACH);
    }
}
