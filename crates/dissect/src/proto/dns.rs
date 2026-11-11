//! DNS (UDP/TCP 53) ve mDNS (UDP 5353), RFC 1035 / RFC 6762.

use std::borrow::Cow;
use std::fmt::Write as _;

use super::util::{bytes_field, is_tcp, str_field, tcp_port, udp_port};
use crate::{
    Ctx, DissectResult, Dissector, Field, FieldDef, FieldType as T, FieldValue as V, Layer,
    NextHint, Reader,
};

/// DNS üzerinden UDP 53.
pub struct Dns;
/// DNS üzerinden TCP 53 (2 bayt uzunluk öneki). Alanları `Dns` ile ortak.
pub struct DnsTcp;
/// Multicast DNS, UDP 5353. Wireshark gibi `dns.*` alanlarını kullanır.
pub struct Mdns;

const HDR: usize = 12;
/// Bir adın çözümünde izlenecek en fazla sıkıştırma işaretçisi.
const MAX_JUMPS: usize = 32;
/// RFC 1035: bir adın kablo biçimindeki en fazla uzunluğu.
const MAX_NAME: usize = 255;

const FIELDS: &[FieldDef] = &[
    FieldDef::new("dns", T::None, "Domain Name System"),
    FieldDef::new("dns.length", T::U16, "Length (TCP)"),
    FieldDef::new("dns.id", T::U16, "Transaction ID"),
    FieldDef::new("dns.flags", T::U16, "Flags"),
    FieldDef::new("dns.flags.response", T::Bool, "Response"),
    FieldDef::new("dns.flags.opcode", T::U8, "Opcode"),
    FieldDef::new("dns.flags.authoritative", T::Bool, "Authoritative"),
    FieldDef::new("dns.flags.truncated", T::Bool, "Truncated"),
    FieldDef::new("dns.flags.recdesired", T::Bool, "Recursion desired"),
    FieldDef::new("dns.flags.recavail", T::Bool, "Recursion available"),
    FieldDef::new("dns.flags.z", T::Bool, "Z (reserved)"),
    FieldDef::new("dns.flags.authenticated", T::Bool, "Answer authenticated"),
    FieldDef::new("dns.flags.checkdisable", T::Bool, "Non-authenticated data"),
    FieldDef::new("dns.flags.rcode", T::U8, "Reply code"),
    FieldDef::new("dns.count.queries", T::U16, "Questions"),
    FieldDef::new("dns.count.answers", T::U16, "Answer RRs"),
    FieldDef::new("dns.count.auth_rr", T::U16, "Authority RRs"),
    FieldDef::new("dns.count.add_rr", T::U16, "Additional RRs"),
    FieldDef::new("dns.queries", T::None, "Queries"),
    FieldDef::new("dns.answers", T::None, "Answers"),
    FieldDef::new("dns.authorities", T::None, "Authoritative nameservers"),
    FieldDef::new("dns.additionals", T::None, "Additional records"),
    FieldDef::new("dns.qry", T::None, "Query"),
    FieldDef::new("dns.qry.name", T::Str, "Query name"),
    FieldDef::new("dns.qry.type", T::U16, "Query type"),
    FieldDef::new("dns.qry.class", T::U16, "Query class"),
    FieldDef::new("dns.rr", T::None, "Resource record"),
    FieldDef::new("dns.resp.name", T::Str, "RR name"),
    FieldDef::new("dns.resp.type", T::U16, "RR type"),
    FieldDef::new("dns.resp.class", T::U16, "RR class"),
    FieldDef::new("dns.resp.ttl", T::U32, "Time to live"),
    FieldDef::new("dns.resp.len", T::U16, "Data length"),
    FieldDef::new("dns.a", T::Ipv4, "IPv4 address"),
    FieldDef::new("dns.aaaa", T::Ipv6, "IPv6 address"),
    FieldDef::new("dns.cname", T::Str, "Canonical name"),
    FieldDef::new("dns.ptr.domain_name", T::Str, "PTR domain name"),
    FieldDef::new("dns.ns", T::Str, "Name server"),
    FieldDef::new("dns.mx.preference", T::U16, "MX preference"),
    FieldDef::new("dns.mx.mail_exchange", T::Str, "Mail exchange"),
    FieldDef::new("dns.txt", T::Str, "TXT string"),
    FieldDef::new("dns.soa.mname", T::Str, "Primary name server"),
    FieldDef::new("dns.soa.rname", T::Str, "Responsible authority's mailbox"),
    FieldDef::new("dns.soa.serial_number", T::U32, "Serial number"),
    FieldDef::new("dns.soa.refresh_interval", T::U32, "Refresh interval"),
    FieldDef::new("dns.soa.retry_interval", T::U32, "Retry interval"),
    FieldDef::new("dns.soa.expire_limit", T::U32, "Expire limit"),
    FieldDef::new("dns.soa.minimum_ttl", T::U32, "Minimum TTL"),
    FieldDef::new("dns.srv.priority", T::U16, "SRV priority"),
    FieldDef::new("dns.srv.weight", T::U16, "SRV weight"),
    FieldDef::new("dns.srv.port", T::U16, "SRV port"),
    FieldDef::new("dns.srv.target", T::Str, "SRV target"),
    FieldDef::new("dns.svcb.svcpriority", T::U16, "SvcPriority (SVCB/HTTPS)"),
    FieldDef::new("dns.svcb.targetname", T::Str, "TargetName (SVCB/HTTPS)"),
    FieldDef::new("dns.data", T::Bytes, "Raw RR data"),
];

const MDNS_FIELDS: &[FieldDef] = &[FieldDef::new(
    "mdns",
    T::None,
    "Multicast Domain Name System",
)];

impl Dissector for Dns {
    fn name(&self) -> &'static str {
        "dns"
    }
    fn display_name(&self) -> &'static str {
        "DNS"
    }
    fn can_dissect(&self, _: &Ctx, hint: &NextHint, data: &[u8]) -> bool {
        !is_tcp(hint) && udp_port(hint, &[53]) && data.len() >= HDR
    }
    fn fields(&self) -> &'static [FieldDef] {
        FIELDS
    }
    fn dissect(&self, ctx: &mut Ctx, data: &[u8], base: usize) -> DissectResult {
        dissect_dns("dns", "Domain Name System", ctx, data, base, false)
    }
}

impl Dissector for DnsTcp {
    fn name(&self) -> &'static str {
        "dns"
    }
    fn display_name(&self) -> &'static str {
        "DNS"
    }
    fn can_dissect(&self, _: &Ctx, hint: &NextHint, data: &[u8]) -> bool {
        tcp_port(hint, &[53]) && data.len() >= 2 + HDR
    }
    /// Alanlar `Dns`'te tanımlı; yinelenmesin diye boş.
    fn fields(&self) -> &'static [FieldDef] {
        &[]
    }
    fn dissect(&self, ctx: &mut Ctx, data: &[u8], base: usize) -> DissectResult {
        dissect_dns("dns", "Domain Name System", ctx, data, base, true)
    }
}

impl Dissector for Mdns {
    fn name(&self) -> &'static str {
        "mdns"
    }
    fn display_name(&self) -> &'static str {
        "MDNS"
    }
    fn can_dissect(&self, _: &Ctx, hint: &NextHint, data: &[u8]) -> bool {
        udp_port(hint, &[5353]) && data.len() >= HDR
    }
    fn fields(&self) -> &'static [FieldDef] {
        MDNS_FIELDS
    }
    fn dissect(&self, ctx: &mut Ctx, data: &[u8], base: usize) -> DissectResult {
        dissect_dns(
            "mdns",
            "Multicast Domain Name System",
            ctx,
            data,
            base,
            false,
        )
    }
}

/// Sıkıştırılmış DNS adını `msg[off..]`'tan okur. `(ad, off'ta tüketilen bayt)`.
/// İşaretçi döngüleri ve aşırı uzun adlar hata döner.
pub(crate) fn read_name(msg: &[u8], off: usize) -> Result<(String, usize), &'static str> {
    const SHORT: &str = "eksik veri";
    let mut name = String::new();
    let mut pos = off;
    let mut consumed = None;
    let (mut jumps, mut wire) = (0usize, 0usize);
    loop {
        let b = *msg.get(pos).ok_or(SHORT)?;
        match b & 0xc0 {
            0x00 if b == 0 => {
                let used = consumed.unwrap_or_else(|| pos + 1 - off);
                if name.is_empty() {
                    name.push_str("<Root>");
                }
                return Ok((name, used));
            }
            0x00 => {
                let n = usize::from(b);
                let label = msg.get(pos + 1..pos + 1 + n).ok_or(SHORT)?;
                wire += 1 + n;
                if wire > MAX_NAME {
                    return Err("ad çok uzun");
                }
                if !name.is_empty() {
                    name.push('.');
                }
                for &c in label {
                    if c.is_ascii_graphic() && c != b'.' && c != b'\\' {
                        name.push(char::from(c));
                    } else {
                        let _ = write!(name, "\\{c:03}");
                    }
                }
                pos += 1 + n;
            }
            0xc0 => {
                let lo = *msg.get(pos + 1).ok_or(SHORT)?;
                if consumed.is_none() {
                    consumed = Some(pos + 2 - off);
                }
                jumps += 1;
                if jumps > MAX_JUMPS {
                    return Err("sıkıştırma işaretçisi döngüsü");
                }
                pos = usize::from(u16::from_be_bytes([b & 0x3f, lo]));
            }
            _ => return Err("geçersiz etiket tipi"),
        }
    }
}

fn type_name(t: u16) -> &'static str {
    match t {
        1 => "A",
        2 => "NS",
        5 => "CNAME",
        6 => "SOA",
        12 => "PTR",
        13 => "HINFO",
        15 => "MX",
        16 => "TXT",
        28 => "AAAA",
        33 => "SRV",
        35 => "NAPTR",
        41 => "OPT",
        43 => "DS",
        46 => "RRSIG",
        47 => "NSEC",
        48 => "DNSKEY",
        64 => "SVCB",
        65 => "HTTPS",
        255 => "ANY",
        257 => "CAA",
        _ => "",
    }
}

fn type_str(t: u16) -> Cow<'static, str> {
    match type_name(t) {
        "" => format!("Unknown ({t})").into(),
        s => s.into(),
    }
}

fn class_str(c: u16) -> Cow<'static, str> {
    match c & 0x7fff {
        1 => "IN".into(),
        3 => "CH".into(),
        4 => "HS".into(),
        255 => "ANY".into(),
        n => format!("0x{n:04x}").into(),
    }
}

fn opcode_name(o: u8) -> Cow<'static, str> {
    match o {
        0 => "Standard query".into(),
        1 => "Inverse query".into(),
        2 => "Server status request".into(),
        4 => "Zone change notification".into(),
        5 => "Dynamic update".into(),
        n => format!("Unknown operation ({n})").into(),
    }
}

fn rcode_name(r: u8) -> Cow<'static, str> {
    match r {
        0 => "No error".into(),
        1 => "Format error".into(),
        2 => "Server failure".into(),
        3 => "No such name".into(),
        4 => "Not implemented".into(),
        5 => "Refused".into(),
        n => format!("Unknown error ({n})").into(),
    }
}

/// DNS iletisi üzerinde gezinme durumu.
struct Msg<'a> {
    data: &'a [u8],
    r: Reader<'a>,
    info: Vec<String>,
}

impl Msg<'_> {
    /// `off`'taki adı okuyup alan üretir; `(alan, ad, tüketilen)`.
    fn name(&self, fname: &'static str, title: &str, off: usize) -> (Field, Option<String>, usize) {
        match read_name(self.data, off) {
            Ok((n, used)) => (
                str_field(fname, title, Some(n.clone()), self.r.abs(off), used),
                Some(n),
                used,
            ),
            Err(e) => (
                Field::new(
                    fname,
                    format!("{title}: [{e}]"),
                    V::None,
                    self.r.abs(off),
                    0,
                )
                .malformed(),
                None,
                0,
            ),
        }
    }

    /// Soru kaydı; başarılıysa sonraki ofset.
    fn question(&mut self, off: usize) -> (Field, Option<usize>) {
        let (nf, name, used) = self.name("dns.qry.name", "Name", off);
        let t_off = off + used;
        let (ty, cl) = (self.r.be_u16(t_off), self.r.be_u16(t_off + 2));
        let mut q = Field::new("dns.qry", "Query", V::None, self.r.abs(off), used + 4);
        q.push(nf);
        let tf = Field::opt("dns.qry.type", "Type", ty.map(V::U16), self.r.abs(t_off), 2);
        q.push(match ty {
            Some(t) => tf.relabel(format!("Type: {} ({t})", type_str(t))),
            None => tf,
        });
        let cf = Field::opt(
            "dns.qry.class",
            "Class",
            cl.map(V::U16),
            self.r.abs(t_off + 2),
            2,
        );
        q.push(match cl {
            Some(c) => cf.relabel(format!("Class: {} (0x{c:04x})", class_str(c))),
            None => cf,
        });
        match (name, ty, cl) {
            (Some(n), Some(t), Some(c)) if used > 0 => {
                q = q.relabel(format!("{n}: type {}, class {}", type_str(t), class_str(c)));
                self.info.push(format!("{} {n}", type_str(t)));
                (q, Some(t_off + 4))
            }
            _ => (q.malformed(), None),
        }
    }

    /// Kaynak kaydı; başarılıysa sonraki ofset.
    fn rr(&mut self, off: usize) -> (Field, Option<usize>) {
        let (nf, name, used) = self.name("dns.resp.name", "Name", off);
        let h = off + used;
        let (ty, cl, ttl, rdlen) = (
            self.r.be_u16(h),
            self.r.be_u16(h + 2),
            self.r.be_u32(h + 4),
            self.r.be_u16(h + 8),
        );
        let mut f = Field::new(
            "dns.rr",
            "Resource record",
            V::None,
            self.r.abs(off),
            used + 10,
        );
        f.push(nf);
        let tf = Field::opt("dns.resp.type", "Type", ty.map(V::U16), self.r.abs(h), 2);
        f.push(match ty {
            Some(t) => tf.relabel(format!("Type: {} ({t})", type_str(t))),
            None => tf,
        });
        let cf = Field::opt(
            "dns.resp.class",
            "Class",
            cl.map(V::U16),
            self.r.abs(h + 2),
            2,
        );
        f.push(match (ty, cl) {
            (Some(41), Some(c)) => cf.relabel(format!("UDP payload size: {c}")),
            (_, Some(c)) => cf.relabel(format!("Class: {} (0x{c:04x})", class_str(c))),
            _ => cf,
        });
        f.push(Field::opt(
            "dns.resp.ttl",
            "Time to live",
            ttl.map(V::U32),
            self.r.abs(h + 4),
            4,
        ));
        f.push(Field::opt(
            "dns.resp.len",
            "Data length",
            rdlen.map(V::U16),
            self.r.abs(h + 8),
            2,
        ));
        let (Some(n), Some(t), Some(c), Some(_), Some(rdlen)) = (name, ty, cl, ttl, rdlen) else {
            return (f.malformed(), None);
        };
        if used == 0 {
            return (f.malformed(), None);
        }
        let rd = h + 10;
        let rdlen = usize::from(rdlen);
        f.len += rdlen;
        let Some(rdata) = self.r.slice(rd, rdlen) else {
            f.push(
                Field::new(
                    "dns.data",
                    "Data: [eksik veri]",
                    V::None,
                    self.r.abs(rd),
                    rdlen,
                )
                .malformed(),
            );
            return (f.malformed(), None);
        };
        let summary = self.rdata(&mut f, t, rd, rdata);
        f = f.relabel(format!(
            "{n}: type {}, class {}{}",
            type_str(t),
            class_str(c),
            if summary.is_empty() {
                String::new()
            } else {
                format!(", {summary}")
            }
        ));
        self.info.push(if summary.is_empty() {
            type_str(t).into_owned()
        } else {
            format!("{} {summary}", type_str(t))
        });
        (f, Some(rd + rdlen))
    }

    /// RDATA alanlarını ekler; info için kısa değer döner.
    fn rdata(&self, f: &mut Field, t: u16, rd: usize, rdata: &[u8]) -> String {
        let end = rd + rdata.len();
        let r = Reader::new(rdata, self.r.abs(rd));
        // RDATA içindeki ad: tüm iletiye göre çözülür ama RDATA'yı aşmamalı.
        let name_in = |fname, title, at: usize| {
            let (mut nf, n, used) = self.name(fname, title, at);
            if at + used > end {
                nf = nf.malformed();
            }
            (nf, n.unwrap_or_default(), at + used)
        };
        match t {
            1 | 28 => {
                let (name, title, v) = if t == 1 {
                    (
                        "dns.a",
                        "Address",
                        r.ipv4(0).filter(|_| rdata.len() == 4).map(V::Ipv4),
                    )
                } else {
                    (
                        "dns.aaaa",
                        "AAAA Address",
                        r.ipv6(0).filter(|_| rdata.len() == 16).map(V::Ipv6),
                    )
                };
                let s = v.as_ref().map(ToString::to_string).unwrap_or_default();
                f.push(Field::opt(name, title, v, r.abs(0), rdata.len()));
                s
            }
            2 | 5 | 12 => {
                let (fname, title) = match t {
                    2 => ("dns.ns", "Name Server"),
                    5 => ("dns.cname", "CNAME"),
                    _ => ("dns.ptr.domain_name", "Domain Name"),
                };
                let (nf, n, _) = name_in(fname, title, rd);
                f.push(nf);
                n
            }
            15 => {
                f.push(Field::opt(
                    "dns.mx.preference",
                    "Preference",
                    r.be_u16(0).map(V::U16),
                    r.abs(0),
                    2,
                ));
                let (nf, n, _) = name_in("dns.mx.mail_exchange", "Mail Exchange", rd + 2);
                f.push(nf);
                format!("{} {n}", r.be_u16(0).unwrap_or(0))
            }
            16 => {
                let mut i = 0;
                while i < rdata.len() {
                    let n = usize::from(rdata[i]);
                    let s = r.slice(i + 1, n);
                    f.push(str_field(
                        "dns.txt",
                        "TXT",
                        s.map(super::util::lossy),
                        r.abs(i),
                        n + 1,
                    ));
                    if s.is_none() {
                        break;
                    }
                    i += n + 1;
                }
                String::new()
            }
            6 => {
                let (nf, mname, at) = name_in("dns.soa.mname", "Primary name server", rd);
                f.push(nf);
                let (nf, _, at) = name_in("dns.soa.rname", "Responsible authority's mailbox", at);
                f.push(nf);
                for (i, (fname, title)) in [
                    ("dns.soa.serial_number", "Serial Number"),
                    ("dns.soa.refresh_interval", "Refresh Interval"),
                    ("dns.soa.retry_interval", "Retry Interval"),
                    ("dns.soa.expire_limit", "Expire limit"),
                    ("dns.soa.minimum_ttl", "Minimum TTL"),
                ]
                .into_iter()
                .enumerate()
                {
                    let o = at + 4 * i;
                    let v = self.r.be_u32(o).filter(|_| o + 4 <= end);
                    f.push(Field::opt(fname, title, v.map(V::U32), self.r.abs(o), 4));
                }
                mname
            }
            33 => {
                let (p, w, port) = (r.be_u16(0), r.be_u16(2), r.be_u16(4));
                f.push(Field::opt(
                    "dns.srv.priority",
                    "Priority",
                    p.map(V::U16),
                    r.abs(0),
                    2,
                ));
                f.push(Field::opt(
                    "dns.srv.weight",
                    "Weight",
                    w.map(V::U16),
                    r.abs(2),
                    2,
                ));
                f.push(Field::opt(
                    "dns.srv.port",
                    "Port",
                    port.map(V::U16),
                    r.abs(4),
                    2,
                ));
                let (nf, n, _) = name_in("dns.srv.target", "Target", rd + 6);
                f.push(nf);
                format!(
                    "{} {} {} {n}",
                    p.unwrap_or(0),
                    w.unwrap_or(0),
                    port.unwrap_or(0)
                )
            }
            64 | 65 => {
                let p = r.be_u16(0);
                f.push(Field::opt(
                    "dns.svcb.svcpriority",
                    "SvcPriority",
                    p.map(V::U16),
                    r.abs(0),
                    2,
                ));
                let (nf, _, at) = name_in("dns.svcb.targetname", "TargetName", rd + 2);
                f.push(nf);
                if at < end {
                    let rest = &rdata[at - rd..];
                    f.push(bytes_field(
                        "dns.data",
                        "SvcParams (raw)",
                        Some(rest),
                        self.r.abs(at),
                        rest.len(),
                    ));
                }
                String::new()
            }
            _ => {
                if !rdata.is_empty() {
                    f.push(bytes_field(
                        "dns.data",
                        "Data",
                        Some(rdata),
                        r.abs(0),
                        rdata.len(),
                    ));
                }
                String::new()
            }
        }
    }
}

fn dissect_dns(
    proto: &'static str,
    title: &'static str,
    ctx: &mut Ctx,
    data: &[u8],
    base: usize,
    tcp: bool,
) -> DissectResult {
    let mut l = Layer::new(proto, title, base, data.len());
    let (msg, mbase) = if tcp {
        let r = Reader::new(data, base);
        let len = r.be_u16(0);
        let mut lf = Field::opt("dns.length", "Length", len.map(V::U16), base, 2);
        let n = len.map_or(0, usize::from);
        if data.len() < 2 + n {
            lf = lf.malformed();
        }
        l.push(lf);
        (
            data.get(2..(2 + n).min(data.len())).unwrap_or(&[]),
            base + 2,
        )
    } else {
        (data, base)
    };
    let r = Reader::new(msg, mbase);
    let id = r.be_u16(0);
    let flags = r.be_u16(2);
    l.push(
        Field::opt("dns.id", "Transaction ID", id.map(V::U16), r.abs(0), 2)
            .relabel(format!("Transaction ID: 0x{:04x}", id.unwrap_or(0))),
    );
    let response = flags.is_some_and(|f| f & 0x8000 != 0);
    let opcode = flags.map_or(0, |f| u8::try_from((f >> 11) & 0xf).unwrap_or(0));
    let rcode = flags.map_or(0, |f| u8::try_from(f & 0xf).unwrap_or(0));
    let mut ff = Field::opt("dns.flags", "Flags", flags.map(V::U16), r.abs(2), 2);
    if let Some(fv) = flags {
        let kind = if response { " response" } else { "" };
        let rc = if response && rcode != 0 {
            format!(", {}", rcode_name(rcode))
        } else {
            String::new()
        };
        ff = ff.relabel(format!(
            "Flags: 0x{fv:04x} {}{kind}{rc}",
            opcode_name(opcode)
        ));
        let bit = |name, title: &str, m: u16| {
            let on = fv & m != 0;
            Field::new(
                name,
                format!("{title}: {}", if on { "Set" } else { "Not set" }),
                V::Bool(on),
                r.abs(2),
                2,
            )
        };
        ff.push(
            bit("dns.flags.response", "Response", 0x8000).relabel(if response {
                "Response: Message is a response"
            } else {
                "Response: Message is a query"
            }),
        );
        ff.push(Field::new(
            "dns.flags.opcode",
            format!("Opcode: {} ({opcode})", opcode_name(opcode)),
            V::U8(opcode),
            r.abs(2),
            2,
        ));
        if response {
            ff.push(bit("dns.flags.authoritative", "Authoritative", 0x0400));
        }
        ff.push(bit("dns.flags.truncated", "Truncated", 0x0200));
        ff.push(bit("dns.flags.recdesired", "Recursion desired", 0x0100));
        if response {
            ff.push(bit("dns.flags.recavail", "Recursion available", 0x0080));
        }
        ff.push(bit("dns.flags.z", "Z", 0x0040));
        ff.push(bit(
            "dns.flags.authenticated",
            "Answer authenticated",
            0x0020,
        ));
        ff.push(bit(
            "dns.flags.checkdisable",
            "Non-authenticated data",
            0x0010,
        ));
        if response {
            ff.push(Field::new(
                "dns.flags.rcode",
                format!("Reply code: {} ({rcode})", rcode_name(rcode)),
                V::U8(rcode),
                r.abs(2),
                2,
            ));
        }
    }
    l.push(ff);
    let counts = [
        ("dns.count.queries", "Questions", r.be_u16(4)),
        ("dns.count.answers", "Answer RRs", r.be_u16(6)),
        ("dns.count.auth_rr", "Authority RRs", r.be_u16(8)),
        ("dns.count.add_rr", "Additional RRs", r.be_u16(10)),
    ];
    for (i, (name, t, v)) in counts.iter().enumerate() {
        l.push(Field::opt(name, t, v.map(V::U16), r.abs(4 + 2 * i), 2));
    }

    let mut m = Msg {
        data: msg,
        r,
        info: Vec::new(),
    };
    let mut off = HDR.min(msg.len());
    let mut ok = msg.len() >= HDR;
    let sections = [
        ("dns.queries", "Queries"),
        ("dns.answers", "Answers"),
        ("dns.authorities", "Authoritative nameservers"),
        ("dns.additionals", "Additional records"),
    ];
    for (i, (name, t)) in sections.iter().enumerate() {
        let n = counts[i].2.unwrap_or(0);
        if !ok || n == 0 {
            continue;
        }
        let start = off;
        let mut sec = Field::new(name, *t, V::None, r.abs(off), 0);
        for _ in 0..n {
            let (f, next) = if i == 0 { m.question(off) } else { m.rr(off) };
            sec.push(f);
            let Some(o) = next else {
                ok = false;
                break;
            };
            off = o;
        }
        sec.len = off - start;
        l.push(sec);
    }

    let used = off + if tcp { 2 } else { 0 };
    l.len = used;
    l.fields.len = used;
    l.set_label(format!(
        "{title} ({})",
        if response { "response" } else { "query" }
    ));
    if let Some(id) = id {
        let mut s = opcode_name(opcode).into_owned();
        if response {
            s.push_str(" response");
        }
        let _ = write!(s, " 0x{id:04x}");
        if response && rcode != 0 {
            let _ = write!(s, " {}", rcode_name(rcode));
        }
        for i in &m.info {
            s.push(' ');
            s.push_str(i);
        }
        m.info.clear();
        ctx.info = Some(s);
    }
    DissectResult::last(l)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::read_name;
    use crate::testutil::{dissect, sweep};
    use crate::FieldValue as V;

    // 192.168.1.10:51234 → 8.8.8.8:53, "example.com A" sorgusu (RD).
    pub(crate) const QUERY: &str = "a0b1c2d3e4f53c22fb1a2b3c0800450000391c46400040114cacc0a8010a08080808c8220035002583e8123401000001000000000000076578616d706c6503636f6d0000010001";
    // 8.8.8.8:53 → 192.168.1.10:51234, cevap: A 93.184.216.34, TTL 3600 (sıkıştırılmış ad).
    pub(crate) const RESPONSE: &str = "a0b1c2d3e4f53c22fb1a2b3c0800450000491c46400040114c9c08080808c0a8010a0035c82200350543123481800001000100000000076578616d706c6503636f6d0000010001c00c0001000100000e1000045db8d822";
    // www.example.com: CNAME + A, NXDOMAIN olmayan; MX/TXT/SOA/AAAA/SRV/HTTPS içeren cevap.
    pub(crate) const RICH: &str = "a0b1c2d3e4f53c22fb1a2b3c08004500011e1c46400040114bc708080808c0a8010a0035c822010ad44ebeef8180000100070001000003777777076578616d706c6503636f6d0000010001c00c000500010000012c0002c010c010000100010000012c00045db8d822c010001c00010000012c001026062800022000010248189325c81946c010000f00010000012c0009000a046d61696cc010c010001000010000012c000c0b763d73706631202d616c6c045f736970045f756470c010002100010000012c000c0000000513c403736970c010c010004100010000012c000b0001000001000302683200c010000600010000012c0035026e73056963616e6e036f726700036e6f6303646e73056963616e6e036f72670078a3f17500001c2000000e100012750000000e10";
    // TCP 53 üzerinde uzunluk önekli sorgu.
    pub(crate) const TCP_QUERY: &str = "a0b1c2d3e4f53c22fb1a2b3c0800450000471c46400040064ca9c0a8010a08080808c82300350000000100000001501801f631dc0000001d123401000001000000000000076578616d706c6503636f6d0000010001";
    // mDNS PTR sorgusu, 224.0.0.251:5353.
    pub(crate) const MDNS: &str = "01005e0000fb3c22fb1a2b3c0800450000441c46400040117bb5c0a8010ae00000fb14e914e90030e8f50000000000010000000000000b5f676f6f676c6563617374045f746370056c6f63616c00000c0001";

    #[test]
    fn query() {
        let d = dissect(QUERY);
        assert_eq!(d.protocols(), ["frame", "eth", "ip", "udp", "dns"]);
        assert_eq!(d.summary.protocol, "DNS");
        assert_eq!(d.summary.info, "Standard query 0x1234 A example.com");
        assert_eq!(d.find("dns.id").unwrap().value, V::U16(0x1234));
        assert_eq!(d.find("dns.flags.response").unwrap().value, V::Bool(false));
        assert_eq!(d.find("dns.flags.recdesired").unwrap().value, V::Bool(true));
        assert_eq!(
            d.find("dns.qry.name").unwrap().value,
            V::Str("example.com".into())
        );
        assert_eq!(d.find("dns.qry.type").unwrap().value, V::U16(1));
        assert!(!d.layer("dns").unwrap().is_malformed());
    }

    #[test]
    fn response() {
        let d = dissect(RESPONSE);
        assert_eq!(
            d.summary.info,
            "Standard query response 0x1234 A example.com A 93.184.216.34"
        );
        assert_eq!(d.find("dns.flags.response").unwrap().value, V::Bool(true));
        assert_eq!(d.find("dns.flags.rcode").unwrap().value, V::U8(0));
        assert_eq!(d.find("dns.count.answers").unwrap().value, V::U16(1));
        assert_eq!(
            d.find("dns.resp.name").unwrap().value,
            V::Str("example.com".into())
        );
        assert_eq!(d.find("dns.resp.ttl").unwrap().value, V::U32(3600));
        assert_eq!(
            d.find("dns.a").unwrap().value,
            V::Ipv4([93, 184, 216, 34].into())
        );
        let l = d.layer("dns").unwrap();
        assert!(!l.is_malformed());
        assert_eq!(l.len, 45);
    }

    #[test]
    fn rich_records() {
        let d = dissect(RICH);
        let l = d.layer("dns").unwrap();
        assert!(!l.is_malformed(), "{l:#?}");
        assert_eq!(
            d.find("dns.cname").unwrap().value,
            V::Str("example.com".into())
        );
        assert_eq!(
            d.find("dns.aaaa").unwrap().value,
            V::Ipv6("2606:2800:220:1:248:1893:25c8:1946".parse().unwrap())
        );
        assert_eq!(d.find("dns.mx.preference").unwrap().value, V::U16(10));
        assert_eq!(
            d.find("dns.mx.mail_exchange").unwrap().value,
            V::Str("mail.example.com".into())
        );
        assert_eq!(
            d.find("dns.txt").unwrap().value,
            V::Str("v=spf1 -all".into())
        );
        assert_eq!(
            d.find("dns.soa.mname").unwrap().value,
            V::Str("ns.icann.org".into())
        );
        assert_eq!(d.find("dns.soa.minimum_ttl").unwrap().value, V::U32(3600));
        assert_eq!(d.find("dns.srv.port").unwrap().value, V::U16(5060));
        assert_eq!(
            d.find("dns.srv.target").unwrap().value,
            V::Str("sip.example.com".into())
        );
        assert_eq!(d.find("dns.svcb.svcpriority").unwrap().value, V::U16(1));
        assert_eq!(
            d.summary.info,
            "Standard query response 0xbeef A www.example.com CNAME example.com A 93.184.216.34 \
             AAAA 2606:2800:220:1:248:1893:25c8:1946 MX 10 mail.example.com TXT \
             SRV 0 5 5060 sip.example.com HTTPS SOA ns.icann.org"
        );
    }

    #[test]
    fn tcp_and_mdns() {
        let d = dissect(TCP_QUERY);
        assert_eq!(d.protocols(), ["frame", "eth", "ip", "tcp", "dns"]);
        assert_eq!(d.find("dns.length").unwrap().value, V::U16(29));
        assert_eq!(d.summary.info, "Standard query 0x1234 A example.com");
        let d = dissect(MDNS);
        assert_eq!(d.protocols(), ["frame", "eth", "ip", "udp", "mdns"]);
        assert_eq!(d.summary.protocol, "MDNS");
        assert_eq!(
            d.summary.info,
            "Standard query 0x0000 PTR _googlecast._tcp.local"
        );
        assert_eq!(
            d.find("dns.qry.name").unwrap().value,
            V::Str("_googlecast._tcp.local".into())
        );
    }

    #[test]
    fn compression_loop() {
        // İşaretçi kendine: 0xc00c @ 12.
        let mut msg = vec![0u8; 12];
        msg.extend_from_slice(&[0xc0, 0x0c]);
        assert!(read_name(&msg, 12).is_err());
        // İki işaretçi birbirine.
        let mut msg = vec![0u8; 12];
        msg.extend_from_slice(&[1, b'a', 0xc0, 0x10, 1, b'b', 0xc0, 0x0c]);
        assert!(read_name(&msg, 12).is_err());
        // Geçerli: ileri işaretçi ve kök.
        assert_eq!(read_name(&[0], 0).unwrap(), ("<Root>".into(), 1));
        // Paket içinde kötü niyetli cevap: malformed işaretlenmeli, panic yok.
        let mut h = RESPONSE.to_owned();
        let at = h.len() - 32; // cevap adındaki c00c işaretçisi
        assert_eq!(&h[at..at + 4], "c00c");
        h.replace_range(at..at + 4, "c01d"); // kendine işaret eden ad
        let d = dissect(&h);
        assert!(d.layer("dns").unwrap().is_malformed());
    }

    #[test]
    fn truncation_sweep() {
        for h in [QUERY, RESPONSE, RICH, TCP_QUERY, MDNS] {
            sweep(h);
        }
    }
}
