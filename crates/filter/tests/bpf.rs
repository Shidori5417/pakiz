#![allow(clippy::unwrap_used)]

mod common;

use common::{hex, ARP, ICMP, MDNS, QINQ, SYNACK, V6};
use pakiz_filter::bpf::{compile, run, SNAPLEN};

fn ok(src: &str, h: &str) -> bool {
    bytes_ok(src, &hex(h))
}

fn bytes_ok(src: &str, data: &[u8]) -> bool {
    let p = compile(src).unwrap_or_else(|e| panic!("{src}: {e}"));
    match run(&p, data) {
        0 => false,
        SNAPLEN => true,
        n => panic!("beklenmeyen dönüş {n}"),
    }
}

#[test]
fn protocols() {
    let all = [SYNACK, MDNS, ARP, QINQ, V6, ICMP];
    let table: [(&str, [bool; 6]); 6] = [
        ("tcp", [true, false, false, false, false, false]),
        ("udp", [false, true, false, false, false, false]),
        ("icmp", [false, false, false, false, false, true]),
        ("arp", [false, false, true, false, false, false]),
        ("ip", [true, true, false, false, false, true]),
        ("ip6", [false, false, false, false, true, false]),
    ];
    for (src, want) in table {
        for (h, w) in all.iter().zip(want) {
            assert_eq!(ok(src, h), w, "{src} / {h}");
        }
    }
}

#[test]
fn tcp_over_ipv6() {
    let mut d = hex(V6);
    d[20] = 6;
    assert!(bytes_ok("tcp", &d));
    assert!(!bytes_ok("udp", &d));
    assert!(bytes_ok("ip6 and tcp", &d));
}

#[test]
fn ports() {
    assert!(ok("port 443", SYNACK));
    assert!(ok("port 51234", SYNACK));
    assert!(!ok("port 80", SYNACK));
    assert!(ok("src port 443", SYNACK));
    assert!(!ok("dst port 443", SYNACK));
    assert!(ok("dst port 51234", SYNACK));
    assert!(ok("udp and port 5353", MDNS));
    assert!(ok("port 5353", MDNS));
    assert!(!ok("port 5353", ARP));
    assert!(!ok("port 0", ICMP));
}

#[test]
fn port_skips_fragments() {
    let mut d = hex(SYNACK);
    d[21] = 0x01; // fragment offset != 0
    assert!(!bytes_ok("port 443", &d));
    assert!(bytes_ok("tcp", &d));
}

#[test]
fn port_with_ip_options() {
    // IHL=6 (4 bayt seçenek): port ofseti X ile kaymalı.
    let mut d = hex(SYNACK);
    d[14] = 0x46;
    d.splice(34..34, [1, 1, 1, 0]);
    assert!(bytes_ok("src port 443", &d));
    assert!(!bytes_ok("src port 257", &d));
}

#[test]
fn hosts() {
    assert!(ok("host 10.0.0.1", SYNACK));
    assert!(ok("host 10.0.0.2", SYNACK));
    assert!(ok("src host 10.0.0.1", SYNACK));
    assert!(!ok("src host 10.0.0.2", SYNACK));
    assert!(ok("dst host 10.0.0.2", SYNACK));
    assert!(ok("dst host 224.0.0.251", MDNS));
    assert!(!ok("host 10.0.0.1", ARP));
}

#[test]
fn combinations() {
    assert!(ok("tcp and port 443", SYNACK));
    assert!(ok("tcp && host 10.0.0.1", SYNACK));
    assert!(!ok("udp and port 443", SYNACK));
    assert!(ok("udp or arp", ARP));
    assert!(ok("not arp", SYNACK));
    assert!(!ok("!arp", ARP));
    assert!(ok("(tcp || udp) and not port 80", MDNS));
    assert!(ok("not (tcp or udp)", ARP));
    assert!(ok(
        "tcp and (src port 443 or dst port 80) and host 10.0.0.2",
        SYNACK
    ));
    assert!(!ok("tcp and not (src port 443 or dst port 80)", SYNACK));
}

#[test]
fn truncated_packets_rejected() {
    let d = hex(SYNACK);
    for n in 0..d.len() {
        // Hiçbir kesik önek panic yapmamalı; kısa olan IP başlığı reddedilir.
        let _ = bytes_ok("tcp and port 443", &d[..n]);
    }
    assert!(!bytes_ok("tcp", &d[..13]));
    assert!(!bytes_ok("port 443", &d[..35]));
}

#[test]
fn jump_offsets_forward_only() {
    let p = compile("(tcp or udp) and (port 1 or port 2 or port 3) and not arp").unwrap();
    // Her atlama programın içinde kalmalı.
    for (i, ins) in p.iter().enumerate() {
        if ins.code & 0x07 == 0x05 {
            assert!(i + 1 + usize::from(ins.jt) < p.len());
            assert!(i + 1 + usize::from(ins.jf) < p.len());
        }
    }
}

#[test]
fn too_large_program_errors() {
    let big = vec!["port 1"; 200].join(" or ");
    assert!(compile(&big).unwrap_err().msg.contains("büyük"));
}

#[test]
fn vlan_tagged_not_matched() {
    // VLAN'sız Ethernet varsayımı: etiketli çerçeve ip/udp/port ile eşleşmez.
    for src in ["ip", "udp", "port 5353", "host 10.1.1.1"] {
        assert!(!ok(src, QINQ), "{src}");
    }
    assert!(ok("not ip", QINQ));
}

#[test]
fn ipv6_host_and_port_unsupported_match_nothing() {
    // host/port yalnızca IPv4 için derlenir.
    assert!(!ok("port 0", V6));
    assert!(!ok("host 0.0.0.0", V6));
    assert!(ok("ip6 or host 1.2.3.4", V6));
}
