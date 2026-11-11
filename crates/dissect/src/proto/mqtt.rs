//! MQTT 3.1/3.1.1 (TCP 1883); MQTT 5 CONNECT özellikleri atlanır.

use super::util::{bytes_field, lossy, str_field, tcp_port};
use crate::{
    Ctx, DissectResult, Dissector, Field, FieldDef, FieldType as T, FieldValue as V, Layer,
    NextHint, Reader,
};

pub struct Mqtt;

const FIELDS: &[FieldDef] = &[
    FieldDef::new("mqtt", T::None, "MQ Telemetry Transport Protocol"),
    FieldDef::new("mqtt.message", T::None, "MQTT control packet"),
    FieldDef::new("mqtt.hdrflags", T::U8, "Header flags"),
    FieldDef::new("mqtt.msgtype", T::U8, "Message type"),
    FieldDef::new("mqtt.dupflag", T::Bool, "DUP flag"),
    FieldDef::new("mqtt.qos", T::U8, "QoS level"),
    FieldDef::new("mqtt.retain", T::Bool, "Retain"),
    FieldDef::new("mqtt.len", T::U32, "Remaining length"),
    FieldDef::new("mqtt.proto_len", T::U16, "Protocol name length"),
    FieldDef::new("mqtt.protoname", T::Str, "Protocol name"),
    FieldDef::new("mqtt.ver", T::U8, "Protocol level"),
    FieldDef::new("mqtt.conflags", T::U8, "Connect flags"),
    FieldDef::new("mqtt.conflag.uname", T::Bool, "User name flag"),
    FieldDef::new("mqtt.conflag.passwd", T::Bool, "Password flag"),
    FieldDef::new("mqtt.conflag.retain", T::Bool, "Will retain"),
    FieldDef::new("mqtt.conflag.qos", T::U8, "Will QoS"),
    FieldDef::new("mqtt.conflag.willflag", T::Bool, "Will flag"),
    FieldDef::new("mqtt.conflag.cleansess", T::Bool, "Clean session"),
    FieldDef::new("mqtt.kalive", T::U16, "Keep alive"),
    FieldDef::new("mqtt.property_len", T::U32, "Properties length (MQTT 5)"),
    FieldDef::new("mqtt.clientid", T::Str, "Client ID"),
    FieldDef::new("mqtt.willtopic", T::Str, "Will topic"),
    FieldDef::new("mqtt.willmsg", T::Bytes, "Will message"),
    FieldDef::new("mqtt.username", T::Str, "User name"),
    FieldDef::new("mqtt.passwd", T::Bytes, "Password"),
    FieldDef::new("mqtt.conack.flags", T::U8, "Acknowledge flags"),
    FieldDef::new("mqtt.conack.val", T::U8, "Return code"),
    FieldDef::new("mqtt.topic", T::Str, "Topic"),
    FieldDef::new("mqtt.msgid", T::U16, "Message identifier"),
    FieldDef::new("mqtt.msg", T::Bytes, "Message"),
    FieldDef::new("mqtt.sub.qos", T::U8, "Requested QoS"),
    FieldDef::new("mqtt.suback.qos", T::U8, "Granted QoS / return code"),
];

fn type_name(t: u8) -> &'static str {
    match t {
        1 => "Connect Command",
        2 => "Connect Ack",
        3 => "Publish Message",
        4 => "Publish Ack",
        5 => "Publish Received",
        6 => "Publish Release",
        7 => "Publish Complete",
        8 => "Subscribe Request",
        9 => "Subscribe Ack",
        10 => "Unsubscribe Request",
        11 => "Unsubscribe Ack",
        12 => "Ping Request",
        13 => "Ping Response",
        14 => "Disconnect Req",
        15 => "Auth",
        _ => "Reserved",
    }
}

/// MQTT kalan uzunluk varint'i (en fazla 4 bayt): `(değer, bayt)`.
fn varint(r: &Reader<'_>, off: usize) -> Option<(u32, usize)> {
    let mut v = 0u32;
    for i in 0..4 {
        let b = r.u8(off + i)?;
        v |= u32::from(b & 0x7f) << (7 * i);
        if b & 0x80 == 0 {
            return Some((v, i + 1));
        }
    }
    None
}

impl Dissector for Mqtt {
    fn name(&self) -> &'static str {
        "mqtt"
    }
    fn display_name(&self) -> &'static str {
        "MQTT"
    }
    fn can_dissect(&self, _: &Ctx, hint: &NextHint, data: &[u8]) -> bool {
        tcp_port(hint, &[1883]) && data.len() >= 2
    }
    fn fields(&self) -> &'static [FieldDef] {
        FIELDS
    }

    fn dissect(&self, ctx: &mut Ctx, data: &[u8], base: usize) -> DissectResult {
        let r = Reader::new(data, base);
        let mut l = Layer::new("mqtt", "MQ Telemetry Transport Protocol", base, data.len());
        let mut info = Vec::new();
        let mut o = 0;
        while o < data.len() {
            let (f, s, next) = message(&r, o);
            l.push(f);
            info.push(s);
            match next {
                Some(n) => o = n,
                None => break,
            }
        }
        if let [one] = info.as_slice() {
            l.set_label(format!("MQ Telemetry Transport Protocol, {one}"));
        }
        ctx.info = Some(info.join(", "));
        DissectResult::last(l)
    }
}

/// Uzunluk önekli UTF-8 dize: `(alan, değer, sonraki ofset)`.
fn mqtt_str(
    r: &Reader<'_>,
    o: usize,
    name: &'static str,
    title: &str,
) -> (Field, Option<String>, usize) {
    let n = r.be_u16(o).map(usize::from);
    let s = n.and_then(|n| r.slice(o + 2, n)).map(lossy);
    let n = n.unwrap_or(0);
    (
        str_field(name, title, s.clone(), r.abs(o), 2 + n),
        s,
        o + 2 + n,
    )
}

fn message(r: &Reader<'_>, o: usize) -> (Field, String, Option<usize>) {
    let hdr = r.u8(o).unwrap_or(0);
    let t = hdr >> 4;
    let name = type_name(t);
    let mut m = Field::new("mqtt.message", name, V::None, r.abs(o), r.len() - o);
    let mut hf = Field::new(
        "mqtt.hdrflags",
        format!("Header Flags: 0x{hdr:02x}, Message Type: {name}"),
        V::U8(hdr),
        r.abs(o),
        1,
    );
    hf.push(Field::new(
        "mqtt.msgtype",
        format!("Message Type: {name} ({t})"),
        V::U8(t),
        r.abs(o),
        1,
    ));
    let qos = (hdr >> 1) & 3;
    if t == 3 {
        hf.push(Field::new(
            "mqtt.dupflag",
            "DUP Flag",
            V::Bool(hdr & 8 != 0),
            r.abs(o),
            1,
        ));
        hf.push(Field::new(
            "mqtt.qos",
            format!("QoS Level: {qos}"),
            V::U8(qos),
            r.abs(o),
            1,
        ));
        hf.push(Field::new(
            "mqtt.retain",
            "Retain",
            V::Bool(hdr & 1 != 0),
            r.abs(o),
            1,
        ));
    }
    m.push(hf);
    let rl = varint(r, o + 1);
    m.push(Field::opt(
        "mqtt.len",
        "Msg Len",
        rl.map(|v| V::U32(v.0)),
        r.abs(o + 1),
        rl.map_or(1, |v| v.1),
    ));
    let Some((rl, rn)) = rl else {
        return (m.malformed(), name.into(), None);
    };
    let start = o + 1 + rn;
    let len = usize::try_from(rl).unwrap_or(usize::MAX);
    let end = start.saturating_add(len);
    m.len = 1 + rn + len;
    let complete = end <= r.len();
    let body = r
        .slice(start, len.min(r.len() - start.min(r.len())))
        .unwrap_or(&[]);
    let b = Reader::new(body, r.abs(start));
    let mut info = name.to_owned();
    match t {
        1 => {
            let (f, proto, mut c) = mqtt_str(&b, 0, "mqtt.protoname", "Protocol Name");
            m.push(f);
            let ver = b.u8(c);
            m.push(Field::opt(
                "mqtt.ver",
                "Version",
                ver.map(V::U8),
                b.abs(c),
                1,
            ));
            let fl = b.u8(c + 1);
            let mut cf = Field::opt(
                "mqtt.conflags",
                "Connect Flags",
                fl.map(V::U8),
                b.abs(c + 1),
                1,
            );
            let flags = fl.unwrap_or(0);
            if fl.is_some() {
                cf = cf.relabel(format!("Connect Flags: 0x{flags:02x}"));
                let a = b.abs(c + 1);
                cf.push(Field::new(
                    "mqtt.conflag.uname",
                    "User Name Flag",
                    V::Bool(flags & 0x80 != 0),
                    a,
                    1,
                ));
                cf.push(Field::new(
                    "mqtt.conflag.passwd",
                    "Password Flag",
                    V::Bool(flags & 0x40 != 0),
                    a,
                    1,
                ));
                cf.push(Field::new(
                    "mqtt.conflag.retain",
                    "Will Retain",
                    V::Bool(flags & 0x20 != 0),
                    a,
                    1,
                ));
                cf.push(Field::new(
                    "mqtt.conflag.qos",
                    format!("QoS Level: {}", (flags >> 3) & 3),
                    V::U8((flags >> 3) & 3),
                    a,
                    1,
                ));
                cf.push(Field::new(
                    "mqtt.conflag.willflag",
                    "Will Flag",
                    V::Bool(flags & 0x04 != 0),
                    a,
                    1,
                ));
                cf.push(Field::new(
                    "mqtt.conflag.cleansess",
                    "Clean Session Flag",
                    V::Bool(flags & 0x02 != 0),
                    a,
                    1,
                ));
            }
            m.push(cf);
            m.push(Field::opt(
                "mqtt.kalive",
                "Keep Alive",
                b.be_u16(c + 2).map(V::U16),
                b.abs(c + 2),
                2,
            ));
            c += 4;
            if ver == Some(5) {
                let pl = varint(&b, c);
                m.push(Field::opt(
                    "mqtt.property_len",
                    "Properties Length",
                    pl.map(|v| V::U32(v.0)),
                    b.abs(c),
                    pl.map_or(1, |v| v.1),
                ));
                c += pl.map_or(1, |(v, n)| n + usize::try_from(v).unwrap_or(usize::MAX - n));
            }
            let (f, _, nc) = mqtt_str(&b, c, "mqtt.clientid", "Client ID");
            m.push(f);
            c = nc;
            if flags & 0x04 != 0 {
                let (f, _, nc) = mqtt_str(&b, c, "mqtt.willtopic", "Will Topic");
                m.push(f);
                let n = b.be_u16(nc).map_or(0, usize::from);
                m.push(bytes_field(
                    "mqtt.willmsg",
                    "Will Message",
                    b.slice(nc + 2, n),
                    b.abs(nc),
                    2 + n,
                ));
                c = nc + 2 + n;
            }
            if flags & 0x80 != 0 {
                let (f, _, nc) = mqtt_str(&b, c, "mqtt.username", "User Name");
                m.push(f);
                c = nc;
            }
            if flags & 0x40 != 0 {
                let n = b.be_u16(c).map_or(0, usize::from);
                m.push(bytes_field(
                    "mqtt.passwd",
                    "Password",
                    b.slice(c + 2, n),
                    b.abs(c),
                    2 + n,
                ));
            }
            if proto.is_some_and(|p| p != "MQTT" && p != "MQIsdp") {
                m = m.malformed();
            }
        }
        2 => {
            m.push(Field::opt(
                "mqtt.conack.flags",
                "Acknowledge Flags",
                b.u8(0).map(V::U8),
                b.abs(0),
                1,
            ));
            let rc = b.u8(1);
            m.push(Field::opt(
                "mqtt.conack.val",
                "Return Code",
                rc.map(V::U8),
                b.abs(1),
                1,
            ));
            if let Some(rc) = rc.filter(|&c| c != 0) {
                info = format!("{name} (rc={rc})");
            }
        }
        3 => {
            let (f, topic, mut c) = mqtt_str(&b, 0, "mqtt.topic", "Topic");
            m.push(f);
            if qos > 0 {
                m.push(Field::opt(
                    "mqtt.msgid",
                    "Message Identifier",
                    b.be_u16(c).map(V::U16),
                    b.abs(c),
                    2,
                ));
                c += 2;
            }
            let n = body.len().saturating_sub(c);
            m.push(bytes_field(
                "mqtt.msg",
                "Message",
                b.slice(c, n),
                b.abs(c),
                n,
            ));
            if let Some(tp) = topic {
                info = format!("{name} [{tp}]");
            }
        }
        8 | 10 => {
            let id = b.be_u16(0);
            m.push(Field::opt(
                "mqtt.msgid",
                "Message Identifier",
                id.map(V::U16),
                b.abs(0),
                2,
            ));
            let mut c = 2;
            let mut topics = Vec::new();
            while c < body.len() {
                let (f, tp, nc) = mqtt_str(&b, c, "mqtt.topic", "Topic");
                let bad = tp.is_none();
                m.push(f);
                if bad {
                    break;
                }
                topics.push(tp.unwrap_or_default());
                c = nc;
                if t == 8 {
                    m.push(Field::opt(
                        "mqtt.sub.qos",
                        "Requested QoS",
                        b.u8(c).map(|q| V::U8(q & 3)),
                        b.abs(c),
                        1,
                    ));
                    c += 1;
                }
            }
            info = format!("{name} (id={}) [{}]", id.unwrap_or(0), topics.join(", "));
        }
        9 => {
            let id = b.be_u16(0);
            m.push(Field::opt(
                "mqtt.msgid",
                "Message Identifier",
                id.map(V::U16),
                b.abs(0),
                2,
            ));
            for i in 2..body.len() {
                m.push(Field::opt(
                    "mqtt.suback.qos",
                    "Granted QoS",
                    b.u8(i).map(V::U8),
                    b.abs(i),
                    1,
                ));
            }
            info = format!("{name} (id={})", id.unwrap_or(0));
        }
        4..=7 | 11 => {
            let id = b.be_u16(0);
            m.push(Field::opt(
                "mqtt.msgid",
                "Message Identifier",
                id.map(V::U16),
                b.abs(0),
                2,
            ));
            info = format!("{name} (id={})", id.unwrap_or(0));
        }
        _ => {}
    }
    m.label = info.clone().into();
    if !complete {
        m = m.malformed();
    }
    (m, info, complete.then_some(end))
}

#[cfg(test)]
pub(crate) mod tests {
    use crate::testutil::{dissect, sweep};
    use crate::FieldValue as V;

    // 192.168.1.10:40000 → 192.168.1.5:1883, MQTT 3.1.1 CONNECT (kullanıcı adı + parola).
    pub(crate) const CONNECT: &str = "a0b1c2d3e4f53c22fb1a2b3c0800450000521c46400040069b00c0a8010ac0a801059c40075b0000000100000001501801f61b2d0000102800044d51545404c2003c000f70616b697a2d73656e736f722d30310003696f740006736563726574";
    // Tek segmentte PUBLISH (QoS 1) + SUBSCRIBE + PINGREQ.
    pub(crate) const MULTI: &str = "a0b1c2d3e4f53c22fb1a2b3c0800450000651c46400040069aedc0a8010ac0a801059c40075b0000000100000001501801f6feae0000321c0014686f6d652f6c6976696e67726f6f6d2f74656d70000132312e35821b0002000b686f6d652f2b2f74656d70010008616c657274732f2300c000";
    // Sunucu → istemci: CONNACK + PINGRESP.
    pub(crate) const CONNACK: &str = "a0b1c2d3e4f53c22fb1a2b3c08004500002e1c46400040069b24c0a80105c0a8010a075b9c400000000100000001501801f696d0000020020000d000";

    #[test]
    fn connect() {
        let d = dissect(CONNECT);
        assert_eq!(d.protocols(), ["frame", "eth", "ip", "tcp", "mqtt"]);
        assert_eq!(d.summary.protocol, "MQTT");
        assert_eq!(d.summary.info, "Connect Command");
        assert_eq!(
            d.find("mqtt.protoname").unwrap().value,
            V::Str("MQTT".into())
        );
        assert_eq!(d.find("mqtt.ver").unwrap().value, V::U8(4));
        assert_eq!(d.find("mqtt.kalive").unwrap().value, V::U16(60));
        assert_eq!(
            d.find("mqtt.clientid").unwrap().value,
            V::Str("pakiz-sensor-01".into())
        );
        assert_eq!(d.find("mqtt.username").unwrap().value, V::Str("iot".into()));
        assert_eq!(
            d.find("mqtt.conflag.cleansess").unwrap().value,
            V::Bool(true)
        );
        assert!(!d.layer("mqtt").unwrap().is_malformed());
    }

    #[test]
    fn multiple_messages() {
        let d = dissect(MULTI);
        assert_eq!(
            d.summary.info,
            "Publish Message [home/livingroom/temp], Subscribe Request (id=2) [home/+/temp, alerts/#], Ping Request"
        );
        let l = d.layer("mqtt").unwrap();
        assert!(!l.is_malformed(), "{l:#?}");
        assert_eq!(l.fields.children.len(), 3);
        assert_eq!(d.find("mqtt.qos").unwrap().value, V::U8(1));
        assert_eq!(d.find("mqtt.msgid").unwrap().value, V::U16(1));
        assert_eq!(d.find("mqtt.msg").unwrap().len, 4);
        assert_eq!(
            d.find("mqtt.topic").unwrap().value,
            V::Str("home/livingroom/temp".into())
        );
        let d = dissect(CONNACK);
        assert_eq!(d.summary.info, "Connect Ack, Ping Response");
        assert_eq!(d.find("mqtt.conack.val").unwrap().value, V::U8(0));
    }

    #[test]
    fn truncation_sweep() {
        for h in [CONNECT, MULTI, CONNACK] {
            sweep(h);
        }
    }
}
