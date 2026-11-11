#![allow(clippy::unwrap_used)]

mod common;

use std::borrow::Cow;

use common::{pkt, ARP, ICMP, MDNS, QINQ, SYNACK, V6};
use pakiz_dissect::{Field, FieldDef, FieldType, FieldValue, Layer};
use pakiz_filter::{complete, validate, FieldCatalog, Filter};

fn m(src: &str, h: &str) -> bool {
    let cat = FieldCatalog::default();
    let f = Filter::compile(src, &cat).unwrap_or_else(|e| panic!("{src}: {e}"));
    let (d, p) = pkt(h);
    f.matches(&d, &p)
}

fn err(src: &str) -> pakiz_filter::FilterError {
    Filter::compile(src, &FieldCatalog::default()).unwrap_err()
}

#[test]
fn protocol_exists() {
    assert!(m("tcp", SYNACK));
    assert!(!m("udp", SYNACK));
    assert!(m("udp", MDNS));
    assert!(m("arp", ARP));
    assert!(m("!arp", SYNACK));
    assert!(!m("!arp", ARP));
    assert!(m("frame", ARP));
    assert!(m("ipv6 && icmpv6", V6));
    assert!(m("tcp.options.mss_val", SYNACK));
}

#[test]
fn boolean_combinations() {
    assert!(m("udp || tcp", SYNACK));
    assert!(!m("udp && tcp", SYNACK));
    assert!(m("arp || ip && tcp", SYNACK));
    assert!(!m("(arp || ip) && udp", SYNACK));
    assert!(m("not (udp or arp)", SYNACK));
    assert!(m("!!tcp", SYNACK));
}

#[test]
fn numeric_operators() {
    assert!(m("frame.len == 74", SYNACK));
    assert!(m("frame.len eq 74", SYNACK));
    assert!(m("frame.len != 75", SYNACK));
    assert!(m("frame.len > 73 && frame.len gt 73", SYNACK));
    assert!(!m("frame.len > 1000", SYNACK));
    assert!(m("frame.len < 75 && frame.len lt 75", SYNACK));
    assert!(m("frame.len >= 74 && frame.len ge 74", SYNACK));
    assert!(m("frame.len <= 74 && frame.len le 74", SYNACK));
    assert!(!m("frame.len ne 74", SYNACK));
    assert!(m("ip.ttl == 0x40", SYNACK));
    assert!(m("tcp.flags == 0x012", SYNACK));
}

#[test]
fn bool_fields() {
    assert!(m("tcp.flags.syn == 1", SYNACK));
    assert!(m("tcp.flags.syn == true", SYNACK));
    assert!(m("tcp.flags.fin == 0", SYNACK));
    assert!(m("tcp.flags.fin == false", SYNACK));
    assert!(!m("tcp.flags.fin == 1", SYNACK));
    assert!(m("tcp.flags.ack != 0", SYNACK));
    assert!(m("tcp.flags.syn", SYNACK));
}

#[test]
fn alias_ports() {
    assert!(m("tcp.port == 443", SYNACK));
    assert!(m("tcp.port == 51234", SYNACK));
    assert!(!m("tcp.port == 80", SYNACK));
    assert!(m("udp.port == 5353", MDNS));
    assert!(!m("udp.port == 5353", SYNACK));
    // "herhangi biri !=" semantiği.
    assert!(m("tcp.port != 443", SYNACK));
    assert!(!m("!(tcp.port == 443)", SYNACK));
    assert!(m("tcp.port", SYNACK));
}

#[test]
fn ip_and_cidr() {
    assert!(m("ip.src == 10.0.0.1", SYNACK));
    assert!(m("ip.dst == 10.0.0.2", SYNACK));
    assert!(!m("ip.src == 10.0.0.2", SYNACK));
    assert!(m("ip.addr == 10.0.0.2", SYNACK));
    assert!(m("ip.addr == 10.0.0.0/8", SYNACK));
    assert!(!m("ip.addr == 192.168.0.0/16", SYNACK));
    assert!(m("ip.addr == 192.168.0.0/16", MDNS));
    assert!(m("ip.dst == 224.0.0.0/4", MDNS));
    assert!(m("ip.src == 0.0.0.0/0", MDNS));
    assert!(m("ip.addr != 10.0.0.0/8", MDNS));
    assert!(m("ip.src > 10.0.0.0 && ip.src < 10.0.0.2", SYNACK));
}

#[test]
fn ipv6_fields() {
    assert!(m("ipv6.src == fe80::1", V6));
    assert!(m("ipv6.addr == fe80::2", V6));
    assert!(m("ipv6.addr == fe80::/10", V6));
    assert!(!m("ipv6.addr == 2001:db8::/32", V6));
    assert!(!m("ipv6.src == fe80::1", SYNACK));
}

#[test]
fn mac_fields() {
    assert!(m("eth.src == 02:00:00:00:00:01", SYNACK));
    assert!(m("eth.addr == 02:00:00:00:00:02", SYNACK));
    assert!(m("eth.dst == ff:ff:ff:ff:ff:ff", ARP));
    assert!(!m("eth.addr == aa:aa:aa:aa:aa:aa", ARP));
    assert!(m("eth.src != ff:ff:ff:ff:ff:ff", ARP));
}

#[test]
fn vlan_multiple_occurrences() {
    assert!(m("vlan.id == 100", QINQ));
    assert!(m("vlan.id == 200", QINQ));
    assert!(!m("vlan.id == 300", QINQ));
    assert!(m("vlan && ip.src == 10.1.1.1", QINQ));
}

#[test]
fn bytes_contains() {
    assert!(m("data.data contains 02:03", MDNS));
    assert!(m("data.data == 01:02:03:04", MDNS));
    assert!(!m("data.data contains 04:05", MDNS));
    assert!(m("frame && !(data.data contains 09:09)", MDNS));
    assert!(m("data.data contains \"cde\" || icmp", ICMP));
}

fn http_packet() -> (pakiz_dissect::Dissection, pakiz_dissect::RawPacket) {
    let (mut d, p) = pkt(SYNACK);
    let mut l = Layer::new("http", "HTTP", 0, 0);
    l.push(Field::new(
        "http.host",
        "Host",
        FieldValue::Str(Cow::Borrowed("www.example.com")),
        0,
        0,
    ));
    d.layers.push(l);
    (d, p)
}

fn http_catalog() -> FieldCatalog {
    let mut defs = pakiz_dissect::Registry::default().all_fields();
    defs.push(FieldDef::new("http.host", FieldType::Str, "Host"));
    defs.push(FieldDef::new("dns", FieldType::None, "DNS"));
    FieldCatalog::new(defs)
}

fn hm(src: &str) -> bool {
    let (d, p) = http_packet();
    Filter::compile(src, &http_catalog())
        .unwrap()
        .matches(&d, &p)
}

#[test]
fn string_ops() {
    assert!(hm("http"));
    assert!(hm("dns || http"));
    assert!(hm("http.host contains \"example\""));
    assert!(!hm("http.host contains \"nope\""));
    assert!(hm("http.host == \"www.example.com\""));
    assert!(hm("http.host != \"x\""));
    assert!(hm("http.host matches \"^www\\\\.ex.*\\\\.com$\""));
    assert!(hm("http.host ~ \"EXAMPLE\" || http.host ~ \"(?i)EXAMPLE\""));
    assert!(!hm("http.host matches \"^example\""));
}

#[test]
fn catalog_adds_protocol_names() {
    let cat = FieldCatalog::new(vec![FieldDef::new("foo.bar", FieldType::U8, "x")]);
    assert_eq!(cat.get("foo").unwrap().ty, FieldType::None);
    assert!(cat.get("http").is_none());
    assert!(FieldCatalog::default().get("tcp").is_some());
}

#[test]
fn unknown_field_with_suggestion() {
    let e = err("tcp.prot == 80");
    assert_eq!(e.span, 0..8);
    assert!(e.msg.starts_with("bilinmeyen alan: tcp.prot"));
    assert!(e.msg.contains("tcp.port"), "{}", e.msg);
    let e = err("udp || xyzzyqq");
    assert_eq!(e.span, 7..14);
    assert!(!e.msg.contains("bunu mu"));
}

#[test]
fn type_errors() {
    let cases = [
        ("ip.src == \"abc\"", 10..15),
        ("ip.src == 10", 10..12),
        ("frame.len == \"x\"", 13..16),
        ("ip.ttl == 256", 10..13),
        ("tcp.flags.syn == 2", 17..18),
        ("tcp.flags.syn > 0", 16..17),
        ("eth.src == 01:02", 11..16),
        ("eth.src > 01:02:03:04:05:06", 10..27),
        ("tcp == 1", 7..8),
        ("frame.time == 1", 14..15),
        ("frame.len contains 1", 19..20),
        ("ip.src == 10.0.0.0/8 && ip.dst > 10.0.0.0/8", 33..43),
        ("ipv6.src == 10.0.0.1", 12..20),
        ("data.data matches \"a\"", 18..21),
        ("data.data == 5", 13..14),
    ];
    for (src, span) in cases {
        let e = err(src);
        assert_eq!(e.span, span, "{src}: {}", e.msg);
    }
}

#[test]
fn string_type_errors() {
    let cat = http_catalog();
    let e = Filter::compile("http.host matches \"(\"", &cat).unwrap_err();
    assert!(e.msg.contains("regex"));
    assert_eq!(e.span, 18..21);
    assert!(Filter::compile("http.host == 1", &cat).is_err());
    assert!(Filter::compile("http.host > \"a\"", &cat).is_err());
}

#[test]
fn syntax_errors_propagate() {
    assert_eq!(err("tcp &&").span, 6..6);
    assert_eq!(err("tcp # 1").span, 4..5);
    assert!(err("").msg.contains("boş"));
}

#[test]
fn validate_helper() {
    let cat = FieldCatalog::default();
    assert!(validate("tcp.port == 80 || udp", &cat).is_ok());
    assert!(validate("tcp.port == ", &cat).is_err());
    assert!(validate("foo", &cat).is_err());
}

#[test]
fn completion() {
    let cat = FieldCatalog::default();
    let c: Vec<_> = complete("tcp.flags.s", &cat)
        .iter()
        .map(|d| d.name)
        .collect();
    assert_eq!(c, ["tcp.flags.syn"]);
    let c: Vec<_> = complete("tcp.", &cat).iter().map(|d| d.name).collect();
    assert!(c.len() > 10);
    assert!(c.windows(2).all(|w| w[0] < w[1]));
    assert!(c.iter().all(|n| n.starts_with("tcp.")));
    assert_eq!(complete("zzz", &cat).len(), 0);
    assert_eq!(complete("", &cat).len(), cat.fields().len());
}

#[test]
fn levenshtein_basic() {
    use pakiz_filter::levenshtein;
    assert_eq!(levenshtein("kitten", "sitting"), 3);
    assert_eq!(levenshtein("", "abc"), 3);
    assert_eq!(levenshtein("abc", "abc"), 0);
}

#[test]
fn error_display() {
    let e = err("foo");
    assert_eq!(e.to_string(), format!("{} (konum 0..3)", e.msg));
}

#[test]
fn arp_fields() {
    assert!(m("arp.opcode == 1", ARP));
    assert!(!m("arp.opcode == 2", ARP));
    assert!(m("arp && !ip", ARP));
}

#[test]
fn icmp_fields() {
    assert!(m("icmp.type == 8", ICMP));
    assert!(m("icmp.type == 8 && ip.addr == 127.0.0.0/8", ICMP));
    assert!(!m("icmp.type == 0", ICMP));
    assert!(m("icmpv6.type == 128", V6));
}

#[test]
fn missing_field_is_false_for_every_op() {
    for op in ["==", "!=", ">", "<", ">=", "<="] {
        assert!(!m(&format!("udp.srcport {op} 1"), SYNACK), "{op}");
    }
    assert!(m("!(udp.srcport == 1)", SYNACK));
}

#[test]
fn qinq_ip_alias() {
    assert!(m("ip.addr == 10.1.1.2 && udp.port == 5353", QINQ));
    assert!(!m("tcp", QINQ));
}

#[test]
fn frame_fields() {
    assert!(m("frame.cap_len == 74", SYNACK));
    assert!(m("frame.time", SYNACK));
    assert!(!m("frame.number", SYNACK));
}

#[test]
fn hex_and_decimal_equal() {
    for (a, b) in [("443", "0x1bb"), ("51234", "0xC822")] {
        assert_eq!(
            m(&format!("tcp.srcport == {a}"), SYNACK),
            m(&format!("tcp.srcport == {b}"), SYNACK)
        );
    }
}

#[test]
fn ipv6_ordering_and_cidr_error() {
    assert!(m("ipv6.src < fe80::2", V6));
    assert!(m("ipv6.dst >= fe80::2", V6));
    assert!(err("ipv6.src < fe80::/10").msg.contains("CIDR"));
}

#[test]
fn u64_range_and_large_numbers() {
    assert!(m("frame.len < 4294967295", SYNACK));
    assert!(err("frame.len == 4294967296").msg.contains("aralık"));
    assert!(err("ip.len == 65536").msg.contains("aralık"));
    assert!(m("ip.len == 65535 || ip.len == 60", SYNACK));
}

#[test]
fn deep_nesting() {
    assert!(m("((((tcp)))) && (((!udp)))", SYNACK));
    assert!(m("!(!(!(udp)))", SYNACK));
}

#[test]
fn string_escapes_in_values() {
    let (mut d, p) = http_packet();
    if let Some(l) = d.layers.last_mut() {
        l.push(Field::new(
            "http.host",
            "Host",
            FieldValue::Str(Cow::Borrowed("a\"b\\c")),
            0,
            0,
        ));
    }
    let cat = http_catalog();
    let f = Filter::compile(r#"http.host == "a\"b\\c""#, &cat).unwrap();
    assert!(f.matches(&d, &p));
    // İkinci örnek eşleşir, ilki eşleşmez: "herhangi biri".
    let f = Filter::compile(r#"http.host contains "\"""#, &cat).unwrap();
    assert!(f.matches(&d, &p));
}

#[test]
fn bytes_out_of_range_is_false() {
    let (mut d, p) = pkt(MDNS);
    let mut l = Layer::new("data", "x", 0, 0);
    l.push(Field::new(
        "data.data",
        "x",
        FieldValue::Bytes {
            offset: 1000,
            len: 4,
        },
        0,
        0,
    ));
    d.layers = vec![l];
    let f = Filter::compile("data.data contains 01:02", &FieldCatalog::default()).unwrap();
    assert!(!f.matches(&d, &p));
    let f = Filter::compile("data.data", &FieldCatalog::default()).unwrap();
    assert!(f.matches(&d, &p));
}

#[test]
fn word_and_symbol_forms_agree() {
    let pairs = [
        ("tcp && !udp", "tcp and not udp"),
        ("udp || arp", "udp or arp"),
        ("tcp.port == 443", "tcp.port eq 443"),
        ("tcp.port != 443", "tcp.port ne 443"),
    ];
    for h in [SYNACK, MDNS, ARP] {
        for (a, b) in pairs {
            assert_eq!(m(a, h), m(b, h), "{a} / {b}");
        }
    }
}

#[test]
fn suggest_close_names() {
    let cat = FieldCatalog::default();
    assert_eq!(cat.suggest("ip.scr"), Some("ip.src"));
    assert_eq!(cat.suggest("tpc"), Some("tcp"));
    assert_eq!(cat.suggest("qqqqqqqqqq"), None);
}

#[test]
fn unknown_field_in_nested_expr_span() {
    let e = err("tcp && (udp || nope.x == 1)");
    assert_eq!(e.span, 15..21);
}

#[test]
fn bool_word_on_non_bool_field_errors() {
    assert!(err("frame.len == true").msg.contains("karşılaştırılamaz"));
    assert!(err("tcp.flags.syn == yes").msg.contains("true/false"));
}
