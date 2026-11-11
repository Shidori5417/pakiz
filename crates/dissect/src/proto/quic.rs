//! QUIC başlıkları (RFC 9000 / RFC 9369). Yük şifreli; deşifre edilmez.

use super::util::{bytes_field, hex, udp_port};
use crate::{
    Ctx, DissectResult, Dissector, Field, FieldDef, FieldType as T, FieldValue as V, Layer,
    NextHint, Reader,
};

pub struct Quic;

const V1: u32 = 1;
const V2: u32 = 0x6b33_43cf;

const FIELDS: &[FieldDef] = &[
    FieldDef::new("quic", T::None, "QUIC IETF"),
    FieldDef::new("quic.header_form", T::U8, "Header form (1 = long)"),
    FieldDef::new("quic.fixed_bit", T::Bool, "Fixed bit"),
    FieldDef::new("quic.long.packet_type", T::U8, "Long packet type"),
    FieldDef::new("quic.version", T::U32, "Version"),
    FieldDef::new("quic.dcil", T::U8, "Destination connection ID length"),
    FieldDef::new("quic.dcid", T::Bytes, "Destination connection ID"),
    FieldDef::new("quic.scil", T::U8, "Source connection ID length"),
    FieldDef::new("quic.scid", T::Bytes, "Source connection ID"),
    FieldDef::new("quic.token_length", T::U64, "Token length"),
    FieldDef::new("quic.token", T::Bytes, "Token"),
    FieldDef::new("quic.length", T::U64, "Length (packet number + payload)"),
    FieldDef::new(
        "quic.supported_version",
        T::U32,
        "Supported version (Version Negotiation)",
    ),
    FieldDef::new("quic.retry_token", T::Bytes, "Retry token"),
    FieldDef::new("quic.retry_integrity_tag", T::Bytes, "Retry integrity tag"),
    FieldDef::new(
        "quic.remaining_payload",
        T::Bytes,
        "Protected payload (incl. packet number)",
    ),
];

/// QUIC değişken uzunluklu tamsayı: `(değer, bayt)`.
pub(crate) fn varint(r: &Reader<'_>, off: usize) -> Option<(u64, usize)> {
    let b = r.u8(off)?;
    let n = 1usize << (b >> 6);
    let raw = r.slice(off, n)?;
    let v = raw[1..]
        .iter()
        .fold(u64::from(b & 0x3f), |a, &x| (a << 8) | u64::from(x));
    Some((v, n))
}

fn version_name(v: u32) -> String {
    match v {
        0 => "Version Negotiation".into(),
        V1 => "1".into(),
        V2 => "2".into(),
        v if v >> 8 == 0x00ff_0000 => format!("draft-{}", v & 0xff),
        v => format!("Unknown (0x{v:08x})"),
    }
}

/// Uzun başlık paket tipi → ad (v2'de kodlama farklı).
fn long_type_name(version: u32, t: u8) -> &'static str {
    let t = if version == V2 { (t + 3) % 4 } else { t };
    match t {
        0 => "Initial",
        1 => "0-RTT",
        2 => "Handshake",
        _ => "Retry",
    }
}

impl Dissector for Quic {
    fn name(&self) -> &'static str {
        "quic"
    }
    fn display_name(&self) -> &'static str {
        "QUIC"
    }
    fn can_dissect(&self, _: &Ctx, hint: &NextHint, data: &[u8]) -> bool {
        // Sabit bit (0x40) zorunlu; Version Negotiation hariç.
        udp_port(hint, &[443])
            && data.len() >= 5
            && (data[0] & 0x40 != 0 || (data[0] & 0x80 != 0 && data[1..5] == [0; 4]))
    }
    fn fields(&self) -> &'static [FieldDef] {
        FIELDS
    }

    fn dissect(&self, ctx: &mut Ctx, data: &[u8], base: usize) -> DissectResult {
        let r = Reader::new(data, base);
        let mut l = Layer::new("quic", "QUIC IETF", base, data.len());
        let mut info = Vec::new();
        let mut o = 0;
        // Birleştirilmiş (coalesced) uzun başlıklı paketler.
        while o < data.len() {
            let first = data[o];
            if first & 0x80 == 0 {
                let mut p = Field::new(
                    "quic.header_form",
                    "QUIC Short Header",
                    V::U8(0),
                    r.abs(o),
                    data.len() - o,
                );
                p.push(Field::new(
                    "quic.fixed_bit",
                    "Fixed Bit",
                    V::Bool(first & 0x40 != 0),
                    r.abs(o),
                    1,
                ));
                let rest = data.get(o + 1..).unwrap_or(&[]);
                p.push(bytes_field(
                    "quic.remaining_payload",
                    "Remaining Payload (DCID + protected)",
                    Some(rest),
                    r.abs(o + 1),
                    rest.len(),
                ));
                l.push(p);
                info.push("Protected Payload".to_owned());
                break;
            }
            let (f, s, next) = long_packet(&r, o);
            l.push(f);
            info.push(s);
            match next {
                Some(n) if n > o => o = n,
                _ => break,
            }
        }
        if let Some(V::U32(v)) = l.find("quic.version").map(|f| f.value.clone()) {
            l.set_label(format!("QUIC IETF, Version {}", version_name(v)));
        }
        ctx.info = Some(info.join(", "));
        DissectResult::last(l)
    }
}

fn long_packet(r: &Reader<'_>, o: usize) -> (Field, String, Option<usize>) {
    let first = r.u8(o).unwrap_or(0);
    let mut p = Field::new(
        "quic.header_form",
        "QUIC Long Header",
        V::U8(1),
        r.abs(o),
        r.len() - o,
    );
    p.push(Field::new(
        "quic.fixed_bit",
        "Fixed Bit",
        V::Bool(first & 0x40 != 0),
        r.abs(o),
        1,
    ));
    let version = r.be_u32(o + 1);
    let pt = (first >> 4) & 3;
    p.push(match version {
        Some(v) => Field::new(
            "quic.version",
            format!("Version: {} (0x{v:08x})", version_name(v)),
            V::U32(v),
            r.abs(o + 1),
            4,
        ),
        None => Field::opt("quic.version", "Version", None, r.abs(o + 1), 4),
    });
    let Some(version) = version else {
        return (p.malformed(), "Long Header".into(), None);
    };
    let vn = version == 0;
    let tname = if vn {
        "Version Negotiation"
    } else {
        long_type_name(version, pt)
    };
    if !vn {
        p.children.insert(
            1,
            Field::new(
                "quic.long.packet_type",
                format!("Packet Type: {tname} ({pt})"),
                V::U8(pt),
                r.abs(o),
                1,
            ),
        );
    }
    p.label = format!("QUIC Long Header, {tname}").into();
    let mut c = o + 5;
    let mut cid = |p: &mut Field, ln: &'static str, n: &'static str, t: &str| -> Option<Vec<u8>> {
        let len = r.u8(c);
        p.push(Field::opt(
            ln,
            &format!("{t} Length"),
            len.map(V::U8),
            r.abs(c),
            1,
        ));
        let len = usize::from(len?);
        let v = r.slice(c + 1, len);
        p.push(bytes_field(n, t, v, r.abs(c + 1), len));
        c += 1 + len;
        v.map(<[u8]>::to_vec)
    };
    let dcid = cid(
        &mut p,
        "quic.dcil",
        "quic.dcid",
        "Destination Connection ID",
    );
    let scid = dcid
        .as_ref()
        .and_then(|_| cid(&mut p, "quic.scil", "quic.scid", "Source Connection ID"));
    let (Some(dcid), Some(scid)) = (dcid, scid) else {
        return (p.malformed(), tname.into(), None);
    };
    let info = format!("{tname}, DCID={}, SCID={}", hex(&dcid), hex(&scid));
    if vn {
        let mut i = c;
        while let Some(v) = r.be_u32(i) {
            p.push(Field::new(
                "quic.supported_version",
                format!("Supported Version: {} (0x{v:08x})", version_name(v)),
                V::U32(v),
                r.abs(i),
                4,
            ));
            i += 4;
        }
        return (p, info, None);
    }
    if tname == "Retry" {
        let n = r.len().saturating_sub(c);
        let tok = n.saturating_sub(16);
        p.push(bytes_field(
            "quic.retry_token",
            "Retry Token",
            r.slice(c, tok),
            r.abs(c),
            tok,
        ));
        let mut tag = bytes_field(
            "quic.retry_integrity_tag",
            "Retry Integrity Tag",
            r.slice(c + tok, 16),
            r.abs(c + tok),
            16,
        );
        if n < 16 {
            tag = tag.malformed();
        }
        p.push(tag);
        return (p, info, None);
    }
    if tname == "Initial" {
        let tl = varint(r, c);
        p.push(Field::opt(
            "quic.token_length",
            "Token Length",
            tl.map(|t| V::U64(t.0)),
            r.abs(c),
            tl.map_or(1, |t| t.1),
        ));
        let Some((tl, tn)) = tl else {
            return (p.malformed(), info, None);
        };
        c += tn;
        let tl = usize::try_from(tl).unwrap_or(usize::MAX);
        if tl > 0 {
            let t = r.slice(c, tl);
            p.push(bytes_field("quic.token", "Token", t, r.abs(c), tl));
            if t.is_none() {
                return (p.malformed(), info, None);
            }
        }
        c += tl;
    }
    let len = varint(r, c);
    p.push(Field::opt(
        "quic.length",
        "Length",
        len.map(|t| V::U64(t.0)),
        r.abs(c),
        len.map_or(1, |t| t.1),
    ));
    let Some((len, ln)) = len else {
        return (p.malformed(), info, None);
    };
    c += ln;
    let n = usize::try_from(len).unwrap_or(usize::MAX);
    let avail = r.len().saturating_sub(c).min(n);
    let mut pl = bytes_field(
        "quic.remaining_payload",
        "Protected Payload (packet number + frames)",
        r.slice(c, avail),
        r.abs(c),
        avail,
    );
    if avail < n {
        pl = pl.malformed();
    }
    p.push(pl);
    p.len = c + avail - o;
    (p, info, c.checked_add(n).filter(|&e| e <= r.len()))
}

#[cfg(test)]
pub(crate) mod tests {
    use crate::testutil::{dissect, sweep};
    use crate::FieldValue as V;

    // 192.168.1.10:54321 → 142.250.184.206:443, QUIC v1 Initial (RFC 9001 A.2
    // örnek DCID 8394c8f03e515708), 1200 bayt'a dolgulu.
    pub(crate) const INITIAL: &str = "a0b1c2d3e4f53c22fb1a2b3c0800450004cc1c46400040111060c0a8010a8efab8ced43101bb04b809fec000000001088394c8f03e5157080000449e0b30557a9fc4e90e33587da2c7ec11365b80a5caef14395e83a8cdf2173c6186abd0f51a3f6489aed3f81d42678cb1d6fb20456a8fb4d9fe23486d92b7dc01264b7095badf04294e7398bde2072c51769bc0e50a2f54799ec3e80d32577ca1c6eb10355a7fa4c9ee13385d82a7ccf1163b6085aacff4193e6388add2f71c41668bb0d5fa1f44698eb3d8fd22476c91b6db00254a6f94b9de03284d7297bce1062b50759abfe4092e53789dc2e70c31567ba0c5ea0f34597ea3c8ed12375c81a6cbf0153a5f84a9cef3183d6287acd1f61b40658aafd4f91e43688db2d7fc21466b90b5daff24496e93b8dd02274c7196bbe0052a4f7499bee3082d52779cc1e60b30557a9fc4e90e33587da2c7ec11365b80a5caef14395e83a8cdf2173c6186abd0f51a3f6489aed3f81d42678cb1d6fb20456a8fb4d9fe23486d92b7dc01264b7095badf04294e7398bde2072c51769bc0e50a2f54799ec3e80d32577ca1c6eb10355a7fa4c9ee13385d82a7ccf1163b6085aacff4193e6388add2f71c41668bb0d5fa1f44698eb3d8fd22476c91b6db00254a6f94b9de03284d7297bce1062b50759abfe4092e53789dc2e70c31567ba0c5ea0f34597ea3c8ed12375c81a6cbf0153a5f84a9cef3183d6287acd1f61b40658aafd4f91e43688db2d7fc21466b90b5daff24496e93b8dd02274c7196bbe0052a4f7499bee3082d52779cc1e60b30557a9fc4e90e33587da2c7ec11365b80a5caef14395e83a8cdf2173c6186abd0f51a3f6489aed3f81d42678cb1d6fb20456a8fb4d9fe23486d92b7dc01264b7095badf04294e7398bde2072c51769bc0e50a2f54799ec3e80d32577ca1c6eb10355a7fa4c9ee13385d82a7ccf1163b6085aacff4193e6388add2f71c41668bb0d5fa1f44698eb3d8fd22476c91b6db00254a6f94b9de03284d7297bce1062b50759abfe4092e53789dc2e70c31567ba0c5ea0f34597ea3c8ed12375c81a6cbf0153a5f84a9cef3183d6287acd1f61b40658aafd4f91e43688db2d7fc21466b90b5daff24496e93b8dd02274c7196bbe0052a4f7499bee3082d52779cc1e60b30557a9fc4e90e33587da2c7ec11365b80a5caef14395e83a8cdf2173c6186abd0f51a3f6489aed3f81d42678cb1d6fb20456a8fb4d9fe23486d92b7dc01264b7095badf04294e7398bde2072c51769bc0e50a2f54799ec3e80d32577ca1c6eb10355a7fa4c9ee13385d82a7ccf1163b6085aacff4193e6388add2f71c41668bb0d5fa1f44698eb3d8fd22476c91b6db00254a6f94b9de03284d7297bce1062b50759abfe4092e53789dc2e70c31567ba0c5ea0f34597ea3c8ed12375c81a6cbf0153a5f84a9cef3183d6287acd1f61b40658aafd4f91e43688db2d7fc21466b90b5daff24496e93b8dd02274c7196bbe0052a4f7499bee3082d52779cc1e60b30557a9fc4e90e33587da2c7ec11365b80a5caef14395e83a8cdf2173c6186abd0f51a3f6489aed3f81d42678cb1d6fb20456a8fb4d9fe23486d92b7dc01264b7095badf04294e7398bde2072c51769bc0e50a2f54799ec3e80d32577ca1c6eb10355a7fa4c9ee13385d82a7ccf1163b6085aacff4193e6388add2f71c41668bb0d5fa1f44698eb3d8fd22476c91b6db00254a6f94b9de03284d7297bc";
    // Short header (1-RTT) paket.
    pub(crate) const SHORT: &str = "a0b1c2d3e4f53c22fb1a2b3c0800450000431c464000401114e98efab8cec0a8010a01bbd431002f00735f8394c8f03e515708000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d";

    #[test]
    fn initial() {
        let d = dissect(INITIAL);
        assert_eq!(d.protocols(), ["frame", "eth", "ip", "udp", "quic"]);
        assert_eq!(d.summary.protocol, "QUIC");
        assert_eq!(d.summary.info, "Initial, DCID=8394c8f03e515708, SCID=");
        assert_eq!(d.find("quic.version").unwrap().value, V::U32(1));
        assert_eq!(d.find("quic.long.packet_type").unwrap().value, V::U8(0));
        assert_eq!(d.find("quic.dcil").unwrap().value, V::U8(8));
        assert_eq!(d.find("quic.scil").unwrap().value, V::U8(0));
        assert_eq!(d.find("quic.token_length").unwrap().value, V::U64(0));
        assert_eq!(d.find("quic.length").unwrap().value, V::U64(1182));
        let dcid = d.find("quic.dcid").unwrap();
        assert_eq!(dcid.len, 8);
        assert!(!d.layer("quic").unwrap().is_malformed());
    }

    #[test]
    fn short_header() {
        let d = dissect(SHORT);
        assert_eq!(d.summary.info, "Protected Payload");
        assert_eq!(d.find("quic.header_form").unwrap().value, V::U8(0));
    }

    #[test]
    fn truncation_sweep() {
        sweep(INITIAL);
        sweep(SHORT);
    }
}
