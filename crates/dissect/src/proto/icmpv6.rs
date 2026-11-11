//! `ICMPv6` (echo ve temel NDP).

use crate::{
    fmt_mac, Ctx, DissectResult, Dissector, Field, FieldDef, FieldType as T, FieldValue as V,
    Layer, NextHint, Reader,
};

pub struct Icmpv6;

const FIELDS: &[FieldDef] = &[
    FieldDef::new("icmpv6", T::None, "Internet Control Message Protocol v6"),
    FieldDef::new("icmpv6.type", T::U8, "Type"),
    FieldDef::new("icmpv6.code", T::U8, "Code"),
    FieldDef::new("icmpv6.checksum", T::U16, "Checksum"),
    FieldDef::new("icmpv6.echo.identifier", T::U16, "Echo identifier"),
    FieldDef::new(
        "icmpv6.echo.sequence_number",
        T::U16,
        "Echo sequence number",
    ),
    FieldDef::new("icmpv6.mtu", T::U32, "MTU"),
    FieldDef::new("icmpv6.nd.ra.cur_hop_limit", T::U8, "Cur hop limit"),
    FieldDef::new("icmpv6.nd.ra.flag", T::U8, "RA flags"),
    FieldDef::new(
        "icmpv6.nd.ra.router_lifetime",
        T::U16,
        "Router lifetime (s)",
    ),
    FieldDef::new("icmpv6.nd.ra.reachable_time", T::U32, "Reachable time (ms)"),
    FieldDef::new("icmpv6.nd.ra.retrans_timer", T::U32, "Retrans timer (ms)"),
    FieldDef::new("icmpv6.nd.ns.target_address", T::Ipv6, "NS target address"),
    FieldDef::new("icmpv6.nd.na.target_address", T::Ipv6, "NA target address"),
    FieldDef::new("icmpv6.nd.na.flag.r", T::Bool, "Router flag"),
    FieldDef::new("icmpv6.nd.na.flag.s", T::Bool, "Solicited flag"),
    FieldDef::new("icmpv6.nd.na.flag.o", T::Bool, "Override flag"),
    FieldDef::new("icmpv6.opt", T::Bytes, "ND option"),
    FieldDef::new("icmpv6.opt.type", T::U8, "ND option type"),
    FieldDef::new(
        "icmpv6.opt.length",
        T::U8,
        "ND option length (8-byte units)",
    ),
    FieldDef::new(
        "icmpv6.opt.src_linkaddr",
        T::Mac,
        "Source link-layer address",
    ),
    FieldDef::new(
        "icmpv6.opt.target_linkaddr",
        T::Mac,
        "Target link-layer address",
    ),
];

fn type_name(t: u8) -> &'static str {
    match t {
        1 => "Destination Unreachable",
        2 => "Packet Too Big",
        3 => "Time Exceeded",
        4 => "Parameter Problem",
        128 => "Echo (ping) request",
        129 => "Echo (ping) reply",
        130 => "Multicast Listener Query",
        131 => "Multicast Listener Report",
        133 => "Router Solicitation",
        134 => "Router Advertisement",
        135 => "Neighbor Solicitation",
        136 => "Neighbor Advertisement",
        137 => "Redirect",
        143 => "Multicast Listener Report Message v2",
        _ => "Unknown",
    }
}

/// NDP seçenekleri; `off`'tan dilim sonuna kadar.
fn nd_options(r: &Reader<'_>, mut off: usize, l: &mut Layer) -> Option<[u8; 6]> {
    let mut lladdr = None;
    while off < r.len() {
        let (t, n) = (r.u8(off), r.u8(off + 1));
        let size = n.map_or(0, |n| usize::from(n) * 8);
        let mut f = Field::new(
            "icmpv6.opt",
            "ICMPv6 Option",
            V::Bytes {
                offset: r.abs(off),
                len: size,
            },
            r.abs(off),
            size,
        );
        f.push(Field::opt(
            "icmpv6.opt.type",
            "Type",
            t.map(V::U8),
            r.abs(off),
            1,
        ));
        f.push(Field::opt(
            "icmpv6.opt.length",
            "Length",
            n.map(V::U8),
            r.abs(off + 1),
            1,
        ));
        if size == 0 || r.slice(off, size).is_none() {
            l.push(f.malformed());
            break;
        }
        let mac = r.mac(off + 2);
        match t {
            Some(1) => {
                f.label = "ICMPv6 Option (Source link-layer address)".into();
                f.push(Field::opt(
                    "icmpv6.opt.src_linkaddr",
                    "Link-layer address",
                    mac.map(V::Mac),
                    r.abs(off + 2),
                    6,
                ));
                lladdr = mac;
            }
            Some(2) => {
                f.label = "ICMPv6 Option (Target link-layer address)".into();
                f.push(Field::opt(
                    "icmpv6.opt.target_linkaddr",
                    "Link-layer address",
                    mac.map(V::Mac),
                    r.abs(off + 2),
                    6,
                ));
                lladdr = mac;
            }
            _ => {}
        }
        l.push(f);
        off += size;
    }
    lladdr
}

impl Dissector for Icmpv6 {
    fn name(&self) -> &'static str {
        "icmpv6"
    }
    fn display_name(&self) -> &'static str {
        "ICMPv6"
    }
    fn can_dissect(&self, _: &Ctx, hint: &NextHint, _: &[u8]) -> bool {
        *hint == NextHint::IpProto(58)
    }
    fn fields(&self) -> &'static [FieldDef] {
        FIELDS
    }

    #[allow(clippy::too_many_lines)]
    fn dissect(&self, ctx: &mut Ctx, data: &[u8], base: usize) -> DissectResult {
        let r = Reader::new(data, base);
        let mut l = Layer::new(
            "icmpv6",
            "Internet Control Message Protocol v6",
            base,
            data.len(),
        );
        let (t, c) = (r.u8(0), r.u8(1));
        let mut tf = Field::opt("icmpv6.type", "Type", t.map(V::U8), r.abs(0), 1);
        if let Some(t) = t {
            tf = tf.relabel(format!("Type: {} ({t})", type_name(t)));
        }
        l.push(tf);
        l.push(Field::opt("icmpv6.code", "Code", c.map(V::U8), r.abs(1), 1));
        let ck = r.be_u16(2);
        let mut cf = Field::opt("icmpv6.checksum", "Checksum", ck.map(V::U16), r.abs(2), 2);
        if let Some(v) = ck {
            cf = cf.relabel(format!("Checksum: 0x{v:04x}"));
        }
        l.push(cf);
        let Some(t) = t else {
            return DissectResult::last(l);
        };
        let mut info = type_name(t).to_owned();
        let mut payload = data.len()..data.len();
        match t {
            128 | 129 => {
                let (id, seq) = (r.be_u16(4), r.be_u16(6));
                l.push(Field::opt(
                    "icmpv6.echo.identifier",
                    "Identifier",
                    id.map(V::U16),
                    r.abs(4),
                    2,
                ));
                l.push(Field::opt(
                    "icmpv6.echo.sequence_number",
                    "Sequence",
                    seq.map(V::U16),
                    r.abs(6),
                    2,
                ));
                if let (Some(i), Some(s)) = (id, seq) {
                    info = format!("{info} id=0x{i:04x}, seq={s}");
                }
                l.len = 8.min(data.len());
                payload = l.len..data.len();
            }
            2 => l.push(Field::opt(
                "icmpv6.mtu",
                "MTU",
                r.be_u32(4).map(V::U32),
                r.abs(4),
                4,
            )),
            133 => {
                if let Some(m) = nd_options(&r, 8, &mut l) {
                    info = format!("{info} from {}", fmt_mac(&m));
                }
            }
            134 => {
                l.push(Field::opt(
                    "icmpv6.nd.ra.cur_hop_limit",
                    "Cur hop limit",
                    r.u8(4).map(V::U8),
                    r.abs(4),
                    1,
                ));
                l.push(Field::opt(
                    "icmpv6.nd.ra.flag",
                    "Flags",
                    r.u8(5).map(V::U8),
                    r.abs(5),
                    1,
                ));
                l.push(Field::opt(
                    "icmpv6.nd.ra.router_lifetime",
                    "Router lifetime (s)",
                    r.be_u16(6).map(V::U16),
                    r.abs(6),
                    2,
                ));
                l.push(Field::opt(
                    "icmpv6.nd.ra.reachable_time",
                    "Reachable time (ms)",
                    r.be_u32(8).map(V::U32),
                    r.abs(8),
                    4,
                ));
                l.push(Field::opt(
                    "icmpv6.nd.ra.retrans_timer",
                    "Retrans timer (ms)",
                    r.be_u32(12).map(V::U32),
                    r.abs(12),
                    4,
                ));
                if let Some(m) = nd_options(&r, 16, &mut l) {
                    info = format!("{info} from {}", fmt_mac(&m));
                }
            }
            135 => {
                let tgt = r.ipv6(8);
                l.push(Field::opt(
                    "icmpv6.nd.ns.target_address",
                    "Target Address",
                    tgt.map(V::Ipv6),
                    r.abs(8),
                    16,
                ));
                if let Some(a) = tgt {
                    info = format!("{info} for {a}");
                }
                if let Some(m) = nd_options(&r, 24, &mut l) {
                    info = format!("{info} from {}", fmt_mac(&m));
                }
            }
            136 => {
                let fl = r.u8(4);
                l.push(Field::opt(
                    "icmpv6.nd.na.flag.r",
                    "Router",
                    fl.map(|f| V::Bool(f & 0x80 != 0)),
                    r.abs(4),
                    1,
                ));
                l.push(Field::opt(
                    "icmpv6.nd.na.flag.s",
                    "Solicited",
                    fl.map(|f| V::Bool(f & 0x40 != 0)),
                    r.abs(4),
                    1,
                ));
                l.push(Field::opt(
                    "icmpv6.nd.na.flag.o",
                    "Override",
                    fl.map(|f| V::Bool(f & 0x20 != 0)),
                    r.abs(4),
                    1,
                ));
                let tgt = r.ipv6(8);
                l.push(Field::opt(
                    "icmpv6.nd.na.target_address",
                    "Target Address",
                    tgt.map(V::Ipv6),
                    r.abs(8),
                    16,
                ));
                if let Some(a) = tgt {
                    info = format!("{info} {a}");
                }
                if let Some(m) = nd_options(&r, 24, &mut l) {
                    info = format!("{info} is at {}", fmt_mac(&m));
                }
            }
            _ => {
                l.len = 4.min(data.len());
                payload = l.len..data.len();
            }
        }
        l.set_label(format!("Internet Control Message Protocol v6, {info}"));
        ctx.info = Some(info);
        DissectResult::new(l, NextHint::None, payload)
    }
}

#[cfg(test)]
mod tests {
    use crate::testutil::{dissect, sweep};
    use crate::FieldValue as V;

    const ECHO: &str = "02000000000202000000000186dd6000000000120040fe800000000000000000000000000001fe8000000000000000000000000000023a0001040000000080000000123400016869";
    const NS: &str = "3333ff00000202000000000186dd6000000000203afffe800000000000000000000000000001ff0200000000000000000001ff0000028700000000000000fe8000000000000000000000000000020101020000000001";

    #[test]
    fn echo() {
        let d = dissect(ECHO);
        assert_eq!(d.summary.protocol, "ICMPv6");
        assert_eq!(d.summary.info, "Echo (ping) request id=0x1234, seq=1");
        assert_eq!(d.find("icmpv6.type").unwrap().value, V::U8(128));
        assert_eq!(d.find("icmpv6.echo.identifier").unwrap().offset, 66);
        assert_eq!(d.find("data.len").unwrap().value, V::U32(2));
    }

    #[test]
    fn neighbor_solicitation() {
        let d = dissect(NS);
        assert_eq!(d.protocols(), ["frame", "eth", "ipv6", "icmpv6"]);
        assert_eq!(
            d.summary.info,
            "Neighbor Solicitation for fe80::2 from 02:00:00:00:00:01"
        );
        assert_eq!(
            d.find("icmpv6.opt.src_linkaddr").unwrap().value,
            V::Mac([2, 0, 0, 0, 0, 1])
        );
        assert!(!d.layer("icmpv6").unwrap().is_malformed());
    }

    #[test]
    fn truncation_sweep() {
        sweep(ECHO);
        sweep(NS);
    }
}
