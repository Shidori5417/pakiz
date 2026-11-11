//! DHCP / BOOTP (UDP 67/68), RFC 2131 / RFC 2132.

use std::fmt::Write as _;

use super::util::{bytes_field, lossy, str_field, udp_port};
use crate::{
    fmt_mac, Ctx, DissectResult, Dissector, Field, FieldDef, FieldType as T, FieldValue as V,
    Layer, NextHint, Reader,
};

pub struct Dhcp;

/// BOOTP sabit başlık uzunluğu (magic cookie hariç).
const BOOTP: usize = 236;
const COOKIE: u32 = 0x6382_5363;

const FIELDS: &[FieldDef] = &[
    FieldDef::new("dhcp", T::None, "Dynamic Host Configuration Protocol"),
    FieldDef::new("dhcp.type", T::U8, "Message type (op)"),
    FieldDef::new("dhcp.hw.type", T::U8, "Hardware type"),
    FieldDef::new("dhcp.hw.len", T::U8, "Hardware address length"),
    FieldDef::new("dhcp.hops", T::U8, "Hops"),
    FieldDef::new("dhcp.id", T::U32, "Transaction ID"),
    FieldDef::new("dhcp.secs", T::U16, "Seconds elapsed"),
    FieldDef::new("dhcp.flags", T::U16, "Bootp flags"),
    FieldDef::new("dhcp.flags.bc", T::Bool, "Broadcast flag"),
    FieldDef::new("dhcp.ip.client", T::Ipv4, "Client IP address"),
    FieldDef::new("dhcp.ip.your", T::Ipv4, "Your (client) IP address"),
    FieldDef::new("dhcp.ip.server", T::Ipv4, "Next server IP address"),
    FieldDef::new("dhcp.ip.relay", T::Ipv4, "Relay agent IP address"),
    FieldDef::new("dhcp.hw.mac_addr", T::Mac, "Client MAC address"),
    FieldDef::new("dhcp.hw.addr", T::Bytes, "Client hardware address"),
    FieldDef::new("dhcp.server", T::Str, "Server host name"),
    FieldDef::new("dhcp.file", T::Str, "Boot file name"),
    FieldDef::new("dhcp.cookie", T::U32, "Magic cookie"),
    FieldDef::new("dhcp.option.type", T::U8, "Option"),
    FieldDef::new("dhcp.option.length", T::U8, "Option length"),
    FieldDef::new("dhcp.option.value", T::Bytes, "Option value"),
    FieldDef::new("dhcp.option.dhcp", T::U8, "DHCP message type"),
    FieldDef::new("dhcp.option.subnet_mask", T::Ipv4, "Subnet mask"),
    FieldDef::new("dhcp.option.router", T::Ipv4, "Router"),
    FieldDef::new(
        "dhcp.option.domain_name_server",
        T::Ipv4,
        "Domain name server",
    ),
    FieldDef::new("dhcp.option.hostname", T::Str, "Host name"),
    FieldDef::new(
        "dhcp.option.requested_ip_address",
        T::Ipv4,
        "Requested IP address",
    ),
    FieldDef::new(
        "dhcp.option.ip_address_lease_time",
        T::U32,
        "IP address lease time",
    ),
    FieldDef::new(
        "dhcp.option.dhcp_server_id",
        T::Ipv4,
        "DHCP server identifier",
    ),
    FieldDef::new(
        "dhcp.option.request_list_item",
        T::U8,
        "Parameter request list item",
    ),
    FieldDef::new("dhcp.option.client_id", T::Bytes, "Client identifier"),
    FieldDef::new("dhcp.option.end", T::U8, "End option"),
    FieldDef::new("dhcp.option.padding", T::Bytes, "Padding"),
];

fn msg_type(t: u8) -> &'static str {
    match t {
        1 => "Discover",
        2 => "Offer",
        3 => "Request",
        4 => "Decline",
        5 => "ACK",
        6 => "NAK",
        7 => "Release",
        8 => "Inform",
        _ => "Unknown",
    }
}

fn option_name(c: u8) -> &'static str {
    match c {
        0 => "Padding",
        1 => "Subnet Mask",
        3 => "Router",
        6 => "Domain Name Server",
        12 => "Host Name",
        15 => "Domain Name",
        28 => "Broadcast Address",
        42 => "NTP Servers",
        50 => "Requested IP Address",
        51 => "IP Address Lease Time",
        53 => "DHCP Message Type",
        54 => "DHCP Server Identifier",
        55 => "Parameter Request List",
        57 => "Maximum DHCP Message Size",
        58 => "Renewal Time Value",
        59 => "Rebinding Time Value",
        60 => "Vendor class identifier",
        61 => "Client identifier",
        81 => "Client Fully Qualified Domain Name",
        119 => "Domain Search",
        121 => "Classless Static Route",
        255 => "End",
        _ => "Unknown",
    }
}

impl Dissector for Dhcp {
    fn name(&self) -> &'static str {
        "dhcp"
    }
    fn display_name(&self) -> &'static str {
        "DHCP"
    }
    fn can_dissect(&self, _: &Ctx, hint: &NextHint, data: &[u8]) -> bool {
        udp_port(hint, &[67, 68]) && data.len() >= 4 && matches!(data[0], 1 | 2)
    }
    fn fields(&self) -> &'static [FieldDef] {
        FIELDS
    }

    fn dissect(&self, ctx: &mut Ctx, data: &[u8], base: usize) -> DissectResult {
        let r = Reader::new(data, base);
        let mut l = Layer::new(
            "dhcp",
            "Dynamic Host Configuration Protocol",
            base,
            data.len(),
        );
        let op = r.u8(0);
        l.push(
            Field::opt("dhcp.type", "Message type", op.map(V::U8), r.abs(0), 1).relabel(format!(
                "Message type: {} ({})",
                if op == Some(1) {
                    "Boot Request"
                } else {
                    "Boot Reply"
                },
                op.unwrap_or(0)
            )),
        );
        let (htype, hlen) = (r.u8(1), r.u8(2));
        l.push(Field::opt(
            "dhcp.hw.type",
            "Hardware type",
            htype.map(V::U8),
            r.abs(1),
            1,
        ));
        l.push(Field::opt(
            "dhcp.hw.len",
            "Hardware address length",
            hlen.map(V::U8),
            r.abs(2),
            1,
        ));
        l.push(Field::opt(
            "dhcp.hops",
            "Hops",
            r.u8(3).map(V::U8),
            r.abs(3),
            1,
        ));
        let xid = r.be_u32(4);
        l.push(
            Field::opt("dhcp.id", "Transaction ID", xid.map(V::U32), r.abs(4), 4)
                .relabel(format!("Transaction ID: 0x{:08x}", xid.unwrap_or(0))),
        );
        l.push(Field::opt(
            "dhcp.secs",
            "Seconds elapsed",
            r.be_u16(8).map(V::U16),
            r.abs(8),
            2,
        ));
        let flags = r.be_u16(10);
        let mut ff = Field::opt("dhcp.flags", "Bootp flags", flags.map(V::U16), r.abs(10), 2);
        if let Some(f) = flags {
            let bc = f & 0x8000 != 0;
            ff = ff.relabel(format!(
                "Bootp flags: 0x{f:04x} ({})",
                if bc { "Broadcast" } else { "Unicast" }
            ));
            ff.push(Field::opt(
                "dhcp.flags.bc",
                "Broadcast flag",
                Some(V::Bool(bc)),
                r.abs(10),
                2,
            ));
        }
        l.push(ff);
        for (i, (name, title)) in [
            ("dhcp.ip.client", "Client IP address"),
            ("dhcp.ip.your", "Your (client) IP address"),
            ("dhcp.ip.server", "Next server IP address"),
            ("dhcp.ip.relay", "Relay agent IP address"),
        ]
        .into_iter()
        .enumerate()
        {
            let o = 12 + 4 * i;
            l.push(Field::opt(name, title, r.ipv4(o).map(V::Ipv4), r.abs(o), 4));
        }
        if htype == Some(1) && hlen == Some(6) {
            let mac = r.mac(28);
            let f = Field::opt(
                "dhcp.hw.mac_addr",
                "Client MAC address",
                mac.map(V::Mac),
                r.abs(28),
                6,
            );
            l.push(f);
        } else {
            let n = usize::from(hlen.unwrap_or(16).min(16));
            l.push(bytes_field(
                "dhcp.hw.addr",
                "Client hardware address",
                r.slice(28, n),
                r.abs(28),
                n,
            ));
        }
        let cstr = |o: usize, n: usize| {
            r.slice(o, n).map(|b| {
                let e = b.iter().position(|&c| c == 0).unwrap_or(b.len());
                if e == 0 {
                    "not given".to_owned()
                } else {
                    lossy(&b[..e])
                }
            })
        };
        l.push(str_field(
            "dhcp.server",
            "Server host name",
            cstr(44, 64),
            r.abs(44),
            64,
        ));
        l.push(str_field(
            "dhcp.file",
            "Boot file name",
            cstr(108, 128),
            r.abs(108),
            128,
        ));
        let cookie = r.be_u32(BOOTP);
        let mut cf = Field::opt(
            "dhcp.cookie",
            "Magic cookie",
            cookie.map(V::U32),
            r.abs(BOOTP),
            4,
        );
        let is_dhcp = cookie == Some(COOKIE);
        if is_dhcp {
            cf = cf.relabel("Magic cookie: DHCP");
        } else if cookie.is_some() {
            cf = cf.malformed();
        }
        l.push(cf);

        let mut mtype = None;
        let mut used = (BOOTP + 4).min(data.len());
        if is_dhcp {
            let mut o = BOOTP + 4;
            while o < data.len() {
                let code = data[o];
                if code == 0 {
                    let n = data[o..].iter().take_while(|&&c| c == 0).count();
                    l.push(bytes_field(
                        "dhcp.option.padding",
                        "Padding",
                        r.slice(o, n),
                        r.abs(o),
                        n,
                    ));
                    o += n;
                    continue;
                }
                if code == 255 {
                    l.push(
                        Field::new(
                            "dhcp.option.type",
                            "Option: (255) End",
                            V::U8(255),
                            r.abs(o),
                            1,
                        )
                        .with_children(vec![Field::new(
                            "dhcp.option.end",
                            "Option End: 255",
                            V::U8(255),
                            r.abs(o),
                            1,
                        )]),
                    );
                    o += 1;
                    // End sonrası dolgu.
                    if o < data.len() {
                        let n = data.len() - o;
                        l.push(bytes_field(
                            "dhcp.option.padding",
                            "Padding",
                            r.slice(o, n),
                            r.abs(o),
                            n,
                        ));
                        o = data.len();
                    }
                    break;
                }
                let len = r.u8(o + 1);
                let n = usize::from(len.unwrap_or(0));
                let val = r.slice(o + 2, n).filter(|_| len.is_some());
                let mut of = Field::new(
                    "dhcp.option.type",
                    format!("Option: ({code}) {}", option_name(code)),
                    V::U8(code),
                    r.abs(o),
                    2 + n,
                );
                of.push(Field::opt(
                    "dhcp.option.length",
                    "Length",
                    len.map(V::U8),
                    r.abs(o + 1),
                    1,
                ));
                let Some(v) = val else {
                    l.push(of.malformed());
                    o = data.len();
                    break;
                };
                let vo = o + 2;
                let vr = Reader::new(v, r.abs(vo));
                let ip_list = |of: &mut Field, name, title: &str| {
                    if v.is_empty() || v.len() % 4 != 0 {
                        of.push(bytes_field(name, title, Some(v), vr.abs(0), v.len()).malformed());
                    }
                    for i in (0..v.len() / 4).map(|i| i * 4) {
                        of.push(Field::opt(
                            name,
                            title,
                            vr.ipv4(i).map(V::Ipv4),
                            vr.abs(i),
                            4,
                        ));
                    }
                };
                match code {
                    53 => {
                        let t = vr.u8(0).filter(|_| v.len() == 1);
                        if let Some(t) = t {
                            mtype = Some(t);
                            of = of.relabel(format!(
                                "Option: (53) DHCP Message Type ({})",
                                msg_type(t)
                            ));
                        }
                        of.push(
                            Field::opt("dhcp.option.dhcp", "DHCP", t.map(V::U8), vr.abs(0), 1)
                                .relabel(format!(
                                    "DHCP: {} ({})",
                                    msg_type(t.unwrap_or(0)),
                                    t.unwrap_or(0)
                                )),
                        );
                    }
                    1 => ip_list(&mut of, "dhcp.option.subnet_mask", "Subnet Mask"),
                    3 => ip_list(&mut of, "dhcp.option.router", "Router"),
                    6 => ip_list(
                        &mut of,
                        "dhcp.option.domain_name_server",
                        "Domain Name Server",
                    ),
                    50 => ip_list(
                        &mut of,
                        "dhcp.option.requested_ip_address",
                        "Requested IP Address",
                    ),
                    54 => ip_list(
                        &mut of,
                        "dhcp.option.dhcp_server_id",
                        "DHCP Server Identifier",
                    ),
                    12 => {
                        let s = lossy(v);
                        of = of.relabel(format!("Option: (12) Host Name ({s})"));
                        of.push(str_field(
                            "dhcp.option.hostname",
                            "Host Name",
                            Some(s),
                            vr.abs(0),
                            n,
                        ));
                    }
                    51 => {
                        let t = vr.be_u32(0).filter(|_| v.len() == 4);
                        let mut f = Field::opt(
                            "dhcp.option.ip_address_lease_time",
                            "IP Address Lease Time",
                            t.map(V::U32),
                            vr.abs(0),
                            4,
                        );
                        if let Some(t) = t {
                            f = f.relabel(format!("IP Address Lease Time: {t} s"));
                        }
                        of.push(f);
                    }
                    55 => {
                        for (i, &c) in v.iter().enumerate() {
                            of.push(Field::new(
                                "dhcp.option.request_list_item",
                                format!("Parameter Request List Item: ({c}) {}", option_name(c)),
                                V::U8(c),
                                vr.abs(i),
                                1,
                            ));
                        }
                    }
                    61 => {
                        let mut f = bytes_field(
                            "dhcp.option.client_id",
                            "Client identifier",
                            Some(v),
                            vr.abs(0),
                            n,
                        );
                        if v.len() == 7 && v[0] == 1 {
                            if let Some(m) = vr.mac(1) {
                                f = f.relabel(format!(
                                    "Client identifier: Ethernet {}",
                                    fmt_mac(&m)
                                ));
                            }
                        }
                        of.push(f);
                    }
                    _ => of.push(bytes_field(
                        "dhcp.option.value",
                        "Value",
                        Some(v),
                        vr.abs(0),
                        n,
                    )),
                }
                l.push(of);
                o += 2 + n;
            }
            used = o.min(data.len());
        }
        l.len = used;
        l.fields.len = used;

        let mut info = match mtype {
            Some(t) => format!("DHCP {}", msg_type(t)),
            None if op == Some(1) => "Boot Request".to_owned(),
            None => "Boot Reply".to_owned(),
        };
        if let Some(x) = xid {
            let _ = write!(info, " - Transaction ID 0x{x:x}");
        }
        if let Some(t) = mtype {
            l.set_label(format!(
                "Dynamic Host Configuration Protocol ({})",
                msg_type(t)
            ));
        }
        ctx.info = Some(info);
        DissectResult::last(l)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use crate::testutil::{dissect, sweep};
    use crate::FieldValue as V;

    // 0.0.0.0:68 → 255.255.255.255:67 DHCP Discover (53,61,50,12,55,end).
    pub(crate) const DISCOVER: &str = "ffffffffffff3c22fb1a2b3c08004500013b1c46400040111d6d00000000ffffffff00440043012792b0010106003d1d4e7a0000000000000000000000000000000000000000000b8201fc4200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000638253633501013d0701000b8201fc423204c0a801640c0a70616b697a2d686f737437060103060f77fcff0000000000000000";
    // 192.168.1.1:67 → 192.168.1.100:68 DHCP Offer (53,54,51,1,3,6,end).
    pub(crate) const OFFER: &str = "a0b1c2d3e4f53c22fb1a2b3c08004500013a1c464000401199b7c0a80101c0a80164004300440126f487020106003d1d4e7a0000000000000000c0a80164c0a8010100000000000b8201fc4200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000638253633501023604c0a801013304000151800104ffffff000304c0a8010106080808080801010101ff0000000000000000";

    #[test]
    fn discover() {
        let d = dissect(DISCOVER);
        assert_eq!(d.protocols(), ["frame", "eth", "ip", "udp", "dhcp"]);
        assert_eq!(d.summary.protocol, "DHCP");
        assert_eq!(d.summary.info, "DHCP Discover - Transaction ID 0x3d1d4e7a");
        assert_eq!(d.find("dhcp.option.dhcp").unwrap().value, V::U8(1));
        assert_eq!(d.find("dhcp.id").unwrap().value, V::U32(0x3d1d_4e7a));
        assert_eq!(
            d.find("dhcp.hw.mac_addr").unwrap().value,
            V::Mac([0x00, 0x0b, 0x82, 0x01, 0xfc, 0x42])
        );
        assert_eq!(
            d.find("dhcp.option.hostname").unwrap().value,
            V::Str("pakiz-host".into())
        );
        assert_eq!(
            d.find("dhcp.option.requested_ip_address").unwrap().value,
            V::Ipv4([192, 168, 1, 100].into())
        );
        assert_eq!(d.find("dhcp.flags.bc").unwrap().value, V::Bool(false));
        assert!(d.find("dhcp.option.end").is_some());
        assert!(!d.layer("dhcp").unwrap().is_malformed());
    }

    #[test]
    fn offer() {
        let d = dissect(OFFER);
        assert_eq!(d.summary.info, "DHCP Offer - Transaction ID 0x3d1d4e7a");
        assert_eq!(
            d.find("dhcp.ip.your").unwrap().value,
            V::Ipv4([192, 168, 1, 100].into())
        );
        assert_eq!(
            d.find("dhcp.option.ip_address_lease_time").unwrap().value,
            V::U32(86400)
        );
        assert_eq!(
            d.find("dhcp.option.router").unwrap().value,
            V::Ipv4([192, 168, 1, 1].into())
        );
        assert_eq!(
            d.find("dhcp.option.subnet_mask").unwrap().value,
            V::Ipv4([255, 255, 255, 0].into())
        );
        assert_eq!(
            d.find("dhcp.option.dhcp_server_id").unwrap().value,
            V::Ipv4([192, 168, 1, 1].into())
        );
        assert!(!d.layer("dhcp").unwrap().is_malformed());
    }

    #[test]
    fn truncation_sweep() {
        sweep(DISCOVER);
        sweep(OFFER);
    }
}
