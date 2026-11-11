//! SSH (RFC 4253): sürüm satırı ve şifrelenmemiş ikili paketler (KEXINIT).

use super::util::{bytes_field, find, lossy, str_field, tcp_port};
use crate::{
    Ctx, DissectResult, Dissector, Field, FieldDef, FieldType as T, FieldValue as V, Layer,
    NextHint, Reader,
};

pub struct Ssh;

/// Makul en büyük ikili paket (RFC 4253 §6.1: en az 35000 desteklenmeli).
const MAX_PACKET: u32 = 35_000;

const NAME_LISTS: [(&str, &str); 10] = [
    ("ssh.kex_algorithms", "kex_algorithms"),
    (
        "ssh.server_host_key_algorithms",
        "server_host_key_algorithms",
    ),
    (
        "ssh.encryption_algorithms_client_to_server",
        "encryption_algorithms_client_to_server",
    ),
    (
        "ssh.encryption_algorithms_server_to_client",
        "encryption_algorithms_server_to_client",
    ),
    (
        "ssh.mac_algorithms_client_to_server",
        "mac_algorithms_client_to_server",
    ),
    (
        "ssh.mac_algorithms_server_to_client",
        "mac_algorithms_server_to_client",
    ),
    (
        "ssh.compression_algorithms_client_to_server",
        "compression_algorithms_client_to_server",
    ),
    (
        "ssh.compression_algorithms_server_to_client",
        "compression_algorithms_server_to_client",
    ),
    (
        "ssh.languages_client_to_server",
        "languages_client_to_server",
    ),
    (
        "ssh.languages_server_to_client",
        "languages_server_to_client",
    ),
];

const FIELDS: &[FieldDef] = &[
    FieldDef::new("ssh", T::None, "SSH Protocol"),
    FieldDef::new("ssh.protocol", T::Str, "Protocol version exchange"),
    FieldDef::new("ssh.packet", T::None, "Binary packet"),
    FieldDef::new("ssh.packet_length", T::U32, "Packet length"),
    FieldDef::new("ssh.padding_length", T::U8, "Padding length"),
    FieldDef::new("ssh.message_code", T::U8, "Message code"),
    FieldDef::new("ssh.cookie", T::Bytes, "KEXINIT cookie"),
    FieldDef::new("ssh.kex_algorithms", T::Str, "kex_algorithms"),
    FieldDef::new(
        "ssh.server_host_key_algorithms",
        T::Str,
        "server_host_key_algorithms",
    ),
    FieldDef::new(
        "ssh.encryption_algorithms_client_to_server",
        T::Str,
        "Encryption c→s",
    ),
    FieldDef::new(
        "ssh.encryption_algorithms_server_to_client",
        T::Str,
        "Encryption s→c",
    ),
    FieldDef::new("ssh.mac_algorithms_client_to_server", T::Str, "MAC c→s"),
    FieldDef::new("ssh.mac_algorithms_server_to_client", T::Str, "MAC s→c"),
    FieldDef::new(
        "ssh.compression_algorithms_client_to_server",
        T::Str,
        "Compression c→s",
    ),
    FieldDef::new(
        "ssh.compression_algorithms_server_to_client",
        T::Str,
        "Compression s→c",
    ),
    FieldDef::new("ssh.languages_client_to_server", T::Str, "Languages c→s"),
    FieldDef::new("ssh.languages_server_to_client", T::Str, "Languages s→c"),
    FieldDef::new(
        "ssh.first_kex_packet_follows",
        T::U8,
        "First KEX packet follows",
    ),
    FieldDef::new("ssh.kex.reserved", T::U32, "Reserved"),
    FieldDef::new("ssh.payload", T::Bytes, "Message payload"),
    FieldDef::new("ssh.padding_string", T::Bytes, "Padding"),
    FieldDef::new("ssh.encrypted_packet", T::Bytes, "Encrypted packet"),
];

fn msg_name(c: u8) -> &'static str {
    match c {
        1 => "Disconnect",
        2 => "Ignore",
        3 => "Unimplemented",
        4 => "Debug",
        5 => "Service Request",
        6 => "Service Accept",
        7 => "Extension Info",
        20 => "Key Exchange Init",
        21 => "New Keys",
        30 => "Elliptic Curve Diffie-Hellman Key Exchange Init",
        31 => "Elliptic Curve Diffie-Hellman Key Exchange Reply",
        50 => "User Authentication Request",
        51 => "User Authentication Failure",
        52 => "User Authentication Success",
        _ => "Unknown",
    }
}

impl Dissector for Ssh {
    fn name(&self) -> &'static str {
        "ssh"
    }
    fn display_name(&self) -> &'static str {
        "SSH"
    }
    fn can_dissect(&self, _: &Ctx, hint: &NextHint, data: &[u8]) -> bool {
        matches!(hint, NextHint::TcpPort { .. })
            && (tcp_port(hint, &[22]) || data.starts_with(b"SSH-"))
    }
    fn fields(&self) -> &'static [FieldDef] {
        FIELDS
    }

    fn dissect(&self, ctx: &mut Ctx, data: &[u8], base: usize) -> DissectResult {
        let r = Reader::new(data, base);
        let mut l = Layer::new("ssh", "SSH Protocol", base, data.len());
        let mut info = Vec::new();
        let mut o = 0;
        if data.starts_with(b"SSH-") {
            let end = find(data, b"\n").map_or(data.len(), |i| i + 1);
            let line = &data[..end];
            let t = line.strip_suffix(b"\n").unwrap_or(line);
            let t = t.strip_suffix(b"\r").unwrap_or(t);
            let s = lossy(t);
            info.push(format!("Protocol ({s})"));
            l.push(str_field("ssh.protocol", "Protocol", Some(s), base, end));
            o = end;
        }
        while o < data.len() {
            let (f, s, next) = packet(&r, o);
            l.push(f);
            info.push(s);
            o = next;
        }
        info.dedup();
        ctx.info = Some(info.join(", "));
        DissectResult::last(l)
    }
}

/// `o`'daki ikili paket. Şifreli görünüyorsa kalan tüm bayt tek alan olur.
fn packet(r: &Reader<'_>, o: usize) -> (Field, String, usize) {
    let rest = r.len() - o;
    let (plen, pad, code) = (r.be_u32(o), r.u8(o + 4), r.u8(o + 5));
    // Şifrelenmemiş paket sezgisi: makul uzunluk, padding ≥ 4, blok hizası 8, bilinen kod.
    let plain = matches!((plen, pad, code), (Some(p), Some(d), Some(c))
        if (6..=MAX_PACKET).contains(&p) && d >= 4 && u32::from(d) < p
            && (p + 4) % 8 == 0 && msg_name(c) != "Unknown");
    let (Some(plen), Some(pad), Some(code), true) = (plen, pad, code, plain) else {
        let f = bytes_field(
            "ssh.encrypted_packet",
            "Encrypted Packet",
            r.slice(o, rest),
            r.abs(o),
            rest,
        );
        return (f, format!("Encrypted packet (len={rest})"), r.len());
    };
    let total = 4 + usize::try_from(plen).unwrap_or(usize::MAX);
    let name = msg_name(code);
    let mut p = Field::new(
        "ssh.packet",
        format!("SSH Packet: {name}"),
        V::None,
        r.abs(o),
        total,
    );
    p.push(Field::new(
        "ssh.packet_length",
        format!("Packet Length: {plen}"),
        V::U32(plen),
        r.abs(o),
        4,
    ));
    p.push(Field::new(
        "ssh.padding_length",
        format!("Padding Length: {pad}"),
        V::U8(pad),
        r.abs(o + 4),
        1,
    ));
    p.push(Field::new(
        "ssh.message_code",
        format!("Message Code: {name} ({code})"),
        V::U8(code),
        r.abs(o + 5),
        1,
    ));
    let pl_len = total - 4 - 1 - usize::from(pad);
    // Mesaj gövdesi (kod hariç), segmentle sınırlı.
    let body_end = (o + 5 + pl_len).min(r.len());
    let body = r
        .slice(o + 6, body_end.saturating_sub(o + 6))
        .unwrap_or(&[]);
    let br = Reader::new(body, r.abs(o + 6));
    if code == 20 {
        kexinit(&mut p, &br);
    } else if !body.is_empty() {
        p.push(bytes_field(
            "ssh.payload",
            "Payload",
            Some(body),
            br.abs(0),
            body.len(),
        ));
    }
    let pad_off = o + 5 + pl_len;
    let padf = bytes_field(
        "ssh.padding_string",
        "Padding String",
        r.slice(pad_off, usize::from(pad)),
        r.abs(pad_off),
        usize::from(pad),
    );
    p.push(padf);
    if o + total > r.len() {
        p = p.malformed();
    }
    (p, name.to_owned(), (o + total).min(r.len()))
}

fn kexinit(p: &mut Field, br: &Reader<'_>) {
    p.push(bytes_field(
        "ssh.cookie",
        "Cookie",
        br.slice(0, 16),
        br.abs(0),
        16,
    ));
    let mut o = 16;
    for (name, title) in NAME_LISTS {
        let n = br.be_u32(o).and_then(|n| usize::try_from(n).ok());
        let s = n.and_then(|n| br.slice(o + 4, n)).map(lossy);
        let Some(n) = n.filter(|_| s.is_some()) else {
            p.push(str_field(name, title, None, br.abs(o), 4));
            return;
        };
        p.push(
            str_field(name, title, s.clone(), br.abs(o + 4), n).relabel(format!(
                "{title} length: {n}, {title}: {}",
                s.unwrap_or_default()
            )),
        );
        o += 4 + n;
    }
    p.push(Field::opt(
        "ssh.first_kex_packet_follows",
        "First KEX Packet Follows",
        br.u8(o).map(V::U8),
        br.abs(o),
        1,
    ));
    p.push(Field::opt(
        "ssh.kex.reserved",
        "Reserved",
        br.be_u32(o + 1).map(V::U32),
        br.abs(o + 1),
        4,
    ));
}

#[cfg(test)]
pub(crate) mod tests {
    use crate::testutil::{dissect, sweep};
    use crate::FieldValue as V;

    // 192.168.1.10:50022 → 192.168.1.1:22, istemci banner'ı.
    pub(crate) const BANNER: &str = "a0b1c2d3e4f53c22fb1a2b3c0800450000501c46400040069b06c0a8010ac0a80101c36600160000000100000001501801f66dab00005353482d322e302d4f70656e5353485f392e367031205562756e74752d337562756e747531330d0a";
    // Sunucu → istemci, banner + KEXINIT aynı segmentte (OpenSSH 9.6 tarzı listeler).
    pub(crate) const KEXINIT: &str = "a0b1c2d3e4f53c22fb1a2b3c0800450001cd1c46400040069989c0a80101c0a8010a0016c3660000000100000001501801f6ada100005353482d322e302d4f70656e5353485f392e360d0a0000018c0814101112131415161718191a1b1c1d1e1f0000002f637572766532353531392d7368613235362c656364682d736861322d6e697374703235362c6578742d696e666f2d73000000187373682d656432353531392c7273612d736861322d3531320000003463686163686132302d706f6c7931333035406f70656e7373682e636f6d2c6165733235362d67636d406f70656e7373682e636f6d0000003463686163686132302d706f6c7931333035406f70656e7373682e636f6d2c6165733235362d67636d406f70656e7373682e636f6d00000036756d61632d3132382d65746d406f70656e7373682e636f6d2c686d61632d736861322d3235362d65746d406f70656e7373682e636f6d00000036756d61632d3132382d65746d406f70656e7373682e636f6d2c686d61632d736861322d3235362d65746d406f70656e7373682e636f6d000000156e6f6e652c7a6c6962406f70656e7373682e636f6d000000156e6f6e652c7a6c6962406f70656e7373682e636f6d000000000000000000000000000000000000000000";

    // Anahtar değişiminden sonra şifreli paket (port 22).
    pub(crate) const ENCRYPTED: &str = "a0b1c2d3e4f53c22fb1a2b3c08004500004c1c46400040069b0ac0a80101c0a8010a0016c3660000000100000001501801f6212e0000a3fe59b40f6ac5207bd6318ce7429df853ae0964bf1a75d02b86e13c97f24da8035eb914";

    #[test]
    fn banner() {
        let d = dissect(BANNER);
        assert_eq!(d.protocols(), ["frame", "eth", "ip", "tcp", "ssh"]);
        assert_eq!(d.summary.protocol, "SSH");
        assert_eq!(
            d.summary.info,
            "Protocol (SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13)"
        );
        assert_eq!(
            d.find("ssh.protocol").unwrap().value,
            V::Str("SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13".into())
        );
    }

    #[test]
    fn kexinit() {
        let d = dissect(KEXINIT);
        let l = d.layer("ssh").unwrap();
        assert!(!l.is_malformed(), "{l:#?}");
        assert_eq!(
            d.summary.info,
            "Protocol (SSH-2.0-OpenSSH_9.6), Key Exchange Init"
        );
        assert_eq!(d.find("ssh.message_code").unwrap().value, V::U8(20));
        assert_eq!(
            d.find("ssh.kex_algorithms").unwrap().value,
            V::Str("curve25519-sha256,ecdh-sha2-nistp256,ext-info-s".into())
        );
        assert_eq!(
            d.find("ssh.server_host_key_algorithms").unwrap().value,
            V::Str("ssh-ed25519,rsa-sha2-512".into())
        );
        assert_eq!(
            d.find("ssh.encryption_algorithms_client_to_server")
                .unwrap()
                .value,
            V::Str("chacha20-poly1305@openssh.com,aes256-gcm@openssh.com".into())
        );
        assert_eq!(
            d.find("ssh.first_kex_packet_follows").unwrap().value,
            V::U8(0)
        );
    }

    #[test]
    fn encrypted() {
        let d = dissect(ENCRYPTED);
        assert_eq!(d.summary.info, "Encrypted packet (len=36)");
        assert_eq!(d.find("ssh.encrypted_packet").unwrap().len, 36);
    }

    #[test]
    fn truncation_sweep() {
        sweep(BANNER);
        sweep(KEXINIT);
        sweep(ENCRYPTED);
    }
}
