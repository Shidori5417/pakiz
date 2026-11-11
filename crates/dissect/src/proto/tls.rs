//! TLS kayıt katmanı ve ClientHello/ServerHello (RFC 5246 / RFC 8446).

use std::borrow::Cow;

use super::util::{bytes_field, lossy, str_field};
use crate::{
    Ctx, DissectResult, Dissector, Field, FieldDef, FieldType as T, FieldValue as V, Layer,
    NextHint, Reader,
};

pub struct Tls;

const FIELDS: &[FieldDef] = &[
    FieldDef::new("tls", T::None, "Transport Layer Security"),
    FieldDef::new("tls.record", T::None, "Record layer"),
    FieldDef::new("tls.record.content_type", T::U8, "Content type"),
    FieldDef::new("tls.record.version", T::U16, "Record version"),
    FieldDef::new("tls.record.length", T::U16, "Record length"),
    FieldDef::new("tls.handshake", T::None, "Handshake protocol"),
    FieldDef::new("tls.handshake.type", T::U8, "Handshake type"),
    FieldDef::new("tls.handshake.length", T::U32, "Handshake length"),
    FieldDef::new("tls.handshake.version", T::U16, "Handshake version"),
    FieldDef::new("tls.handshake.random", T::Bytes, "Random"),
    FieldDef::new(
        "tls.handshake.session_id_length",
        T::U8,
        "Session ID length",
    ),
    FieldDef::new("tls.handshake.session_id", T::Bytes, "Session ID"),
    FieldDef::new(
        "tls.handshake.cipher_suites_length",
        T::U16,
        "Cipher suites length",
    ),
    FieldDef::new("tls.handshake.ciphersuites", T::None, "Cipher suites"),
    FieldDef::new("tls.handshake.ciphersuite", T::U16, "Cipher suite"),
    FieldDef::new(
        "tls.handshake.comp_methods_length",
        T::U8,
        "Compression methods length",
    ),
    FieldDef::new("tls.handshake.comp_method", T::U8, "Compression method"),
    FieldDef::new(
        "tls.handshake.extensions_length",
        T::U16,
        "Extensions length",
    ),
    FieldDef::new("tls.handshake.extension.type", T::U16, "Extension type"),
    FieldDef::new("tls.handshake.extension.len", T::U16, "Extension length"),
    FieldDef::new("tls.handshake.extension.data", T::Bytes, "Extension data"),
    FieldDef::new(
        "tls.handshake.extensions_server_name",
        T::Str,
        "Server Name (SNI)",
    ),
    FieldDef::new("tls.handshake.extensions_alpn_str", T::Str, "ALPN protocol"),
    FieldDef::new(
        "tls.handshake.extensions.supported_version",
        T::U16,
        "Supported version",
    ),
    FieldDef::new("tls.change_cipher_spec", T::None, "Change Cipher Spec"),
    FieldDef::new("tls.alert_message", T::None, "Alert"),
    FieldDef::new("tls.alert_message.level", T::U8, "Alert level"),
    FieldDef::new("tls.alert_message.desc", T::U8, "Alert description"),
    FieldDef::new("tls.app_data", T::Bytes, "Encrypted application data"),
];

/// Kayıt başlığı sezgisi: içerik tipi 20..=24, sürüm 0x03 0x00..=0x04.
fn looks_like_record(d: &[u8]) -> bool {
    d.len() >= 5 && (20..=24).contains(&d[0]) && d[1] == 3 && d[2] <= 4
}

fn version_name(v: u16) -> Cow<'static, str> {
    match v {
        0x0300 => "SSL 3.0".into(),
        0x0301 => "TLS 1.0".into(),
        0x0302 => "TLS 1.1".into(),
        0x0303 => "TLS 1.2".into(),
        0x0304 => "TLS 1.3".into(),
        v if v & 0x0f0f == 0x0a0a && v >> 8 == v & 0xff => "Reserved (GREASE)".into(),
        v => format!("Unknown (0x{v:04x})").into(),
    }
}

fn content_name(t: u8) -> &'static str {
    match t {
        20 => "Change Cipher Spec",
        21 => "Alert",
        22 => "Handshake",
        23 => "Application Data",
        24 => "Heartbeat",
        _ => "Unknown",
    }
}

fn handshake_name(t: u8) -> Option<&'static str> {
    Some(match t {
        0 => "Hello Request",
        1 => "Client Hello",
        2 => "Server Hello",
        4 => "New Session Ticket",
        5 => "End Of Early Data",
        8 => "Encrypted Extensions",
        11 => "Certificate",
        12 => "Server Key Exchange",
        13 => "Certificate Request",
        14 => "Server Hello Done",
        15 => "Certificate Verify",
        16 => "Client Key Exchange",
        20 => "Finished",
        24 => "Key Update",
        _ => return None,
    })
}

/// Bilinen şifre takımları; diğerleri onaltılık gösterilir.
fn cipher_name(c: u16) -> Option<&'static str> {
    Some(match c {
        0x1301 => "TLS_AES_128_GCM_SHA256",
        0x1302 => "TLS_AES_256_GCM_SHA384",
        0x1303 => "TLS_CHACHA20_POLY1305_SHA256",
        0x1304 => "TLS_AES_128_CCM_SHA256",
        0x1305 => "TLS_AES_128_CCM_8_SHA256",
        0xc02b => "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
        0xc02f => "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        0xc02c => "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
        0xc030 => "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        0xcca9 => "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
        0xcca8 => "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
        0xccaa => "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
        0xc009 => "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
        0xc00a => "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
        0xc013 => "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
        0xc014 => "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
        0xc023 => "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
        0xc024 => "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
        0xc027 => "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
        0xc028 => "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
        0x009c => "TLS_RSA_WITH_AES_128_GCM_SHA256",
        0x009d => "TLS_RSA_WITH_AES_256_GCM_SHA384",
        0x009e => "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
        0x009f => "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
        0x002f => "TLS_RSA_WITH_AES_128_CBC_SHA",
        0x0035 => "TLS_RSA_WITH_AES_256_CBC_SHA",
        0x003c => "TLS_RSA_WITH_AES_128_CBC_SHA256",
        0x003d => "TLS_RSA_WITH_AES_256_CBC_SHA256",
        0x0033 => "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
        0x0039 => "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
        0x000a => "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
        0x00ff => "TLS_EMPTY_RENEGOTIATION_INFO_SCSV",
        0x5600 => "TLS_FALLBACK_SCSV",
        _ => return None,
    })
}

fn extension_name(t: u16) -> &'static str {
    match t {
        0 => "server_name",
        1 => "max_fragment_length",
        5 => "status_request",
        10 => "supported_groups",
        11 => "ec_point_formats",
        13 => "signature_algorithms",
        16 => "application_layer_protocol_negotiation",
        18 => "signed_certificate_timestamp",
        21 => "padding",
        23 => "extended_master_secret",
        27 => "compress_certificate",
        35 => "session_ticket",
        41 => "pre_shared_key",
        42 => "early_data",
        43 => "supported_versions",
        45 => "psk_key_exchange_modes",
        51 => "key_share",
        17513 => "application_settings",
        65037 => "encrypted_client_hello",
        65281 => "renegotiation_info",
        t if t & 0x0f0f == 0x0a0a => "Reserved (GREASE)",
        _ => "Unknown",
    }
}

impl Dissector for Tls {
    fn name(&self) -> &'static str {
        "tls"
    }
    fn display_name(&self) -> &'static str {
        "TLS"
    }
    /// 443 dahil her TCP portunda kayıt başlığı sezgisi gerekir; aksi halde
    /// şifreli devam segmentleri yanlışlıkla TLS sayılırdı.
    fn can_dissect(&self, _: &Ctx, hint: &NextHint, data: &[u8]) -> bool {
        matches!(hint, NextHint::TcpPort { .. }) && looks_like_record(data)
    }
    fn fields(&self) -> &'static [FieldDef] {
        FIELDS
    }

    fn dissect(&self, ctx: &mut Ctx, data: &[u8], base: usize) -> DissectResult {
        let r = Reader::new(data, base);
        let mut l = Layer::new("tls", "Transport Layer Security", base, data.len());
        let mut info: Vec<String> = Vec::new();
        let mut o = 0;
        while o < data.len() {
            let (ct, ver, len) = (r.u8(o), r.be_u16(o + 1), r.be_u16(o + 3));
            let (Some(ct), Some(ver), Some(len)) = (ct, ver, len) else {
                l.push(
                    Field::new(
                        "tls.record",
                        "Record: [eksik veri]",
                        V::None,
                        r.abs(o),
                        data.len() - o,
                    )
                    .malformed(),
                );
                break;
            };
            if o > 0 && !looks_like_record(&data[o..]) {
                // Önceki kaydın devamı değilse ayrıştırmayı bırak.
                l.push(bytes_field(
                    "tls.app_data",
                    "Unparsed data",
                    data.get(o..),
                    r.abs(o),
                    data.len() - o,
                ));
                break;
            }
            let n = usize::from(len);
            let frag = r.slice(o + 5, n);
            let mut rec = Field::new(
                "tls.record",
                format!("{} Record Layer: {}", version_name(ver), content_name(ct)),
                V::None,
                r.abs(o),
                5 + n,
            );
            rec.push(Field::new(
                "tls.record.content_type",
                format!("Content Type: {} ({ct})", content_name(ct)),
                V::U8(ct),
                r.abs(o),
                1,
            ));
            rec.push(Field::new(
                "tls.record.version",
                format!("Version: {} (0x{ver:04x})", version_name(ver)),
                V::U16(ver),
                r.abs(o + 1),
                2,
            ));
            let mut lf = Field::opt(
                "tls.record.length",
                "Length",
                Some(V::U16(len)),
                r.abs(o + 3),
                2,
            );
            if frag.is_none() {
                lf = lf.relabel(format!(
                    "Length: {len} [segment {} bayt içeriyor, yeniden birleştirme gerekli]",
                    data.len() - o - 5
                ));
            }
            rec.push(lf);
            let avail = data.get(o + 5..).map_or(&[][..], |d| &d[..n.min(d.len())]);
            let fr = Reader::new(avail, r.abs(o + 5));
            match ct {
                22 => {
                    let mut ho = 0;
                    while ho < avail.len() {
                        let (f, name, next) = handshake(&fr, ho, frag.is_some());
                        rec.push(f);
                        info.push(name);
                        match next {
                            Some(x) => ho = x,
                            None => break,
                        }
                    }
                }
                20 => {
                    rec.push(Field::new(
                        "tls.change_cipher_spec",
                        "Change Cipher Spec Message",
                        V::None,
                        fr.abs(0),
                        avail.len(),
                    ));
                    info.push("Change Cipher Spec".into());
                }
                21 => {
                    let mut a = Field::new(
                        "tls.alert_message",
                        "Alert Message",
                        V::None,
                        fr.abs(0),
                        avail.len(),
                    );
                    if n == 2 {
                        a.push(Field::opt(
                            "tls.alert_message.level",
                            "Level",
                            fr.u8(0).map(V::U8),
                            fr.abs(0),
                            1,
                        ));
                        a.push(Field::opt(
                            "tls.alert_message.desc",
                            "Description",
                            fr.u8(1).map(V::U8),
                            fr.abs(1),
                            1,
                        ));
                    } else {
                        a = a.relabel("Alert Message: Encrypted Alert");
                    }
                    rec.push(a);
                    info.push(if n == 2 {
                        "Alert".into()
                    } else {
                        "Encrypted Alert".into()
                    });
                }
                23 => {
                    rec.push(bytes_field(
                        "tls.app_data",
                        "Encrypted Application Data",
                        Some(avail),
                        fr.abs(0),
                        avail.len(),
                    ));
                    info.push("Application Data".into());
                }
                _ => info.push(content_name(ct).into()),
            }
            l.push(rec);
            o += 5 + n;
        }
        info.dedup();
        ctx.info = Some(info.join(", "));
        DissectResult::last(l)
    }
}

/// `fr[ho..]`'daki el sıkışma iletisi: `(alan, info metni, sonraki ofset)`.
/// `complete`: kayıt parçası segmentte tam mı (değilse eksik veri malformed sayılmaz).
fn handshake(fr: &Reader<'_>, ho: usize, complete: bool) -> (Field, String, Option<usize>) {
    let ty = fr.u8(ho);
    let hlen = fr
        .slice(ho + 1, 3)
        .map(|b| u32::from_be_bytes([0, b[0], b[1], b[2]]));
    let name = ty.and_then(handshake_name);
    let total = hlen.and_then(|h| usize::try_from(h).ok()).map(|h| h + 4);
    // Şifreli el sıkışma: bilinmeyen tip ya da uzunluk parçayı aşıyor (tam kayıtta).
    let fits = total.is_some_and(|t| ho + t <= fr.len());
    if name.is_none() || (complete && !fits) {
        let f = bytes_field(
            "tls.handshake",
            "Encrypted Handshake Message",
            fr.slice(ho, fr.len() - ho),
            fr.abs(ho),
            fr.len() - ho,
        );
        return (f, "Encrypted Handshake Message".into(), None);
    }
    let (Some(ty), Some(name), Some(hlen), Some(total)) = (ty, name, hlen, total) else {
        let f = Field::new(
            "tls.handshake",
            "Handshake Protocol: [eksik veri]",
            V::None,
            fr.abs(ho),
            0,
        )
        .malformed();
        return (f, "Handshake".into(), None);
    };
    let mut hs = Field::new(
        "tls.handshake",
        format!("Handshake Protocol: {name}"),
        V::None,
        fr.abs(ho),
        total,
    );
    hs.push(Field::new(
        "tls.handshake.type",
        format!("Handshake Type: {name} ({ty})"),
        V::U8(ty),
        fr.abs(ho),
        1,
    ));
    hs.push(Field::new(
        "tls.handshake.length",
        format!("Length: {hlen}"),
        V::U32(hlen),
        fr.abs(ho + 1),
        3,
    ));
    let body_len = total - 4;
    let body = fr
        .slice(ho + 4, body_len.min(fr.len().saturating_sub(ho + 4)))
        .unwrap_or(&[]);
    let br = Reader::new(body, fr.abs(ho + 4));
    let mut info = name.to_owned();
    if ty == 1 || ty == 2 {
        let sni = hello(&mut hs, &br, ty == 1);
        if let Some(s) = sni {
            info = format!("{name} (SNI={s})");
        }
    }
    let next = (ho + total <= fr.len()).then_some(ho + total);
    (hs, info, next)
}

/// Client/Server Hello gövdesi; varsa SNI döner.
fn hello(hs: &mut Field, br: &Reader<'_>, client: bool) -> Option<String> {
    let ver = br.be_u16(0);
    hs.push(match ver {
        Some(v) => Field::new(
            "tls.handshake.version",
            format!("Version: {} (0x{v:04x})", version_name(v)),
            V::U16(v),
            br.abs(0),
            2,
        ),
        None => Field::opt("tls.handshake.version", "Version", None, br.abs(0), 2),
    });
    hs.push(bytes_field(
        "tls.handshake.random",
        "Random",
        br.slice(2, 32),
        br.abs(2),
        32,
    ));
    let sid_len = br.u8(34);
    hs.push(Field::opt(
        "tls.handshake.session_id_length",
        "Session ID Length",
        sid_len.map(V::U8),
        br.abs(34),
        1,
    ));
    let sl = usize::from(sid_len?);
    if sl > 0 {
        hs.push(bytes_field(
            "tls.handshake.session_id",
            "Session ID",
            br.slice(35, sl),
            br.abs(35),
            sl,
        ));
    }
    let mut o = 35 + sl;
    let cipher = |c: u16, at: usize| {
        let n = cipher_name(c).map_or_else(
            || format!("Unknown (0x{c:04x})"),
            |n| format!("{n} (0x{c:04x})"),
        );
        Field::new(
            "tls.handshake.ciphersuite",
            format!("Cipher Suite: {n}"),
            V::U16(c),
            br.abs(at),
            2,
        )
    };
    if client {
        let cl = br.be_u16(o);
        hs.push(Field::opt(
            "tls.handshake.cipher_suites_length",
            "Cipher Suites Length",
            cl.map(V::U16),
            br.abs(o),
            2,
        ));
        let cl = usize::from(cl?);
        let mut cs = Field::new(
            "tls.handshake.ciphersuites",
            format!("Cipher Suites ({} suites)", cl / 2),
            V::None,
            br.abs(o + 2),
            cl,
        );
        for i in (0..cl / 2).map(|i| o + 2 + 2 * i) {
            let Some(c) = br.be_u16(i) else {
                cs = cs.malformed();
                break;
            };
            cs.push(cipher(c, i));
        }
        hs.push(cs);
        o += 2 + cl;
        let ml = br.u8(o);
        hs.push(Field::opt(
            "tls.handshake.comp_methods_length",
            "Compression Methods Length",
            ml.map(V::U8),
            br.abs(o),
            1,
        ));
        let ml = usize::from(ml?);
        for i in 0..ml {
            hs.push(Field::opt(
                "tls.handshake.comp_method",
                "Compression Method",
                br.u8(o + 1 + i).map(V::U8),
                br.abs(o + 1 + i),
                1,
            ));
        }
        o += 1 + ml;
    } else {
        let c = br.be_u16(o);
        hs.push(match c {
            Some(c) => cipher(c, o),
            None => Field::opt(
                "tls.handshake.ciphersuite",
                "Cipher Suite",
                None,
                br.abs(o),
                2,
            ),
        });
        hs.push(Field::opt(
            "tls.handshake.comp_method",
            "Compression Method",
            br.u8(o + 2).map(V::U8),
            br.abs(o + 2),
            1,
        ));
        o += 3;
    }
    if o >= br.len() {
        return None;
    }
    let el = br.be_u16(o);
    hs.push(Field::opt(
        "tls.handshake.extensions_length",
        "Extensions Length",
        el.map(V::U16),
        br.abs(o),
        2,
    ));
    let end = o + 2 + usize::from(el?);
    o += 2;
    let mut sni = None;
    while o < end {
        let (Some(et), Some(len)) = (br.be_u16(o), br.be_u16(o + 2)) else {
            hs.push(
                Field::new(
                    "tls.handshake.extension.type",
                    "Extension: [eksik veri]",
                    V::None,
                    br.abs(o),
                    0,
                )
                .malformed(),
            );
            break;
        };
        let n = usize::from(len);
        let mut ef = Field::new(
            "tls.handshake.extension.type",
            format!("Extension: {} (len={len})", extension_name(et)),
            V::U16(et),
            br.abs(o),
            4 + n,
        );
        ef.push(Field::new(
            "tls.handshake.extension.len",
            format!("Length: {len}"),
            V::U16(len),
            br.abs(o + 2),
            2,
        ));
        let Some(ed) = br.slice(o + 4, n).filter(|_| o + 4 + n <= end) else {
            hs.push(ef.malformed());
            break;
        };
        let er = Reader::new(ed, br.abs(o + 4));
        match et {
            0 if client => {
                // server_name_list: u16 liste uzunluğu, (tip u8, u16 uzunluk, ad)*.
                let mut i = 2;
                while i + 3 <= ed.len() {
                    let nl = usize::from(er.be_u16(i + 1).unwrap_or(0));
                    let name = er.slice(i + 3, nl).map(lossy);
                    let bad = name.is_none();
                    if er.u8(i) == Some(0) && sni.is_none() {
                        sni.clone_from(&name);
                    }
                    let mut f = str_field(
                        "tls.handshake.extensions_server_name",
                        "Server Name",
                        name,
                        er.abs(i + 3),
                        nl,
                    );
                    if bad {
                        f = f.malformed();
                    }
                    ef.push(f);
                    i += 3 + nl;
                }
            }
            16 => {
                let mut i = 2;
                while i < ed.len() {
                    let pl = usize::from(ed[i]);
                    let p = er.slice(i + 1, pl).map(lossy);
                    let bad = p.is_none();
                    ef.push(str_field(
                        "tls.handshake.extensions_alpn_str",
                        "ALPN Next Protocol",
                        p,
                        er.abs(i + 1),
                        pl,
                    ));
                    if bad {
                        break;
                    }
                    i += 1 + pl;
                }
            }
            43 => {
                let (start, step_end) = if client { (1, ed.len()) } else { (0, ed.len()) };
                let mut i = start;
                while i + 2 <= step_end {
                    let v = er.be_u16(i).unwrap_or(0);
                    ef.push(Field::new(
                        "tls.handshake.extensions.supported_version",
                        format!("Supported Version: {} (0x{v:04x})", version_name(v)),
                        V::U16(v),
                        er.abs(i),
                        2,
                    ));
                    i += 2;
                }
            }
            _ => {
                if n > 0 {
                    ef.push(bytes_field(
                        "tls.handshake.extension.data",
                        "Data",
                        Some(ed),
                        er.abs(0),
                        n,
                    ));
                }
            }
        }
        hs.push(ef);
        o += 4 + n;
    }
    // ServerHello supported_versions = TLS 1.3 → etikette belirt.
    if !client {
        let v13 = hs
            .find("tls.handshake.extensions.supported_version")
            .is_some_and(|f| f.value == V::U16(0x0304));
        if v13 {
            hs.label = format!("{} (TLS 1.3)", hs.label).into();
        }
    }
    sni
}

#[cfg(test)]
pub(crate) mod tests {
    use crate::testutil::{dissect, sweep};
    use crate::FieldValue as V;

    // 192.168.1.10:51500 → 93.184.216.34:443, TLS 1.3 ClientHello (SNI, ALPN h2/http1.1,
    // supported_versions, GREASE, key_share).
    pub(crate) const CLIENT_HELLO: &str = "a0b1c2d3e4f53c22fb1a2b3c08004500014d1c464000400625d8c0a8010a5db8d822c92c01bb0000000100000001501801f60863000016030101200100011c0303000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff00200a0a130113021303c02bc02fc02cc030cca9cca8c013c014009c009d002f0035010000b30a0a000000000010000e00000b6578616d706c652e636f6d00170000ff01000100000a00080006001d00170018000b00020100002300000010000e000c02683208687474702f312e31000500050100000000000d001200100403080404010503080505010806060100120000003300260024001d0020404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f002d00020101002b0007063a3a03040303001b00030200021a1a000100";
    // 443 → istemci: ServerHello (TLS 1.3) + ChangeCipherSpec + Application Data.
    pub(crate) const SERVER_HELLO: &str = "a0b1c2d3e4f53c22fb1a2b3c0800450000c61c4640004006265f5db8d822c0a8010a01bbc92c0000000100000001501801f625a80000160303007a020000760303808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f20e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff130100002e002b0002030400330024001d0020202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f1403030001011703030014a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3";

    #[test]
    fn client_hello() {
        let d = dissect(CLIENT_HELLO);
        assert_eq!(d.protocols(), ["frame", "eth", "ip", "tcp", "tls"]);
        assert_eq!(d.summary.protocol, "TLS");
        assert_eq!(d.summary.info, "Client Hello (SNI=example.com)");
        assert_eq!(d.find("tls.record.content_type").unwrap().value, V::U8(22));
        assert_eq!(d.find("tls.record.version").unwrap().value, V::U16(0x0301));
        assert_eq!(d.find("tls.handshake.type").unwrap().value, V::U8(1));
        assert_eq!(
            d.find("tls.handshake.version").unwrap().value,
            V::U16(0x0303)
        );
        assert_eq!(
            d.find("tls.handshake.ciphersuite").unwrap().value,
            V::U16(0x0a0a)
        );
        assert_eq!(
            d.find("tls.handshake.extensions_server_name")
                .unwrap()
                .value,
            V::Str("example.com".into())
        );
        assert_eq!(
            d.find("tls.handshake.extensions_alpn_str").unwrap().value,
            V::Str("h2".into())
        );
        let l = d.layer("tls").unwrap();
        assert!(!l.is_malformed(), "{l:#?}");
        let suites = l.find("tls.handshake.ciphersuites").unwrap();
        assert_eq!(suites.children.len(), 16);
        assert!(suites.children[1].label.contains("TLS_AES_128_GCM_SHA256"));
        let sv: Vec<_> = l
            .find("tls.handshake")
            .unwrap()
            .children
            .iter()
            .filter(|c| c.value == V::U16(43))
            .flat_map(|c| c.children.iter().skip(1).map(|v| v.value.clone()))
            .collect();
        assert!(sv.contains(&V::U16(0x0304)));
    }

    #[test]
    fn server_hello_multi_record() {
        let d = dissect(SERVER_HELLO);
        assert_eq!(
            d.summary.info,
            "Server Hello, Change Cipher Spec, Application Data"
        );
        let l = d.layer("tls").unwrap();
        assert!(!l.is_malformed(), "{l:#?}");
        assert_eq!(
            d.find("tls.handshake.ciphersuite").unwrap().value,
            V::U16(0x1301)
        );
        assert!(l.find("tls.handshake").unwrap().label.contains("TLS 1.3"));
        assert_eq!(l.fields.children.len(), 3);
    }

    #[test]
    fn truncation_sweep() {
        sweep(CLIENT_HELLO);
        sweep(SERVER_HELLO);
    }
}
