//! `cargo bench -p pakiz-dissect`: tipik paketlerin tam dissect süresi.

#![allow(clippy::unwrap_used)]

use std::hint::black_box;
use std::time::SystemTime;

use criterion::{criterion_group, criterion_main, Criterion};
use pakiz_dissect::{RawPacket, Registry};

/// TCP SYN-ACK (MSS/SACK/TS/WS seçenekli).
const TCP_SYN: &str = "02000000000202000000000108004500003c1c46400040060a740a0000010a00000201bbc8220000000000000001a012ffff00000000020405b40402080a000000010000000201030307";
/// DNS cevabı: example.com A 93.184.216.34.
const DNS_RESPONSE: &str = "a0b1c2d3e4f53c22fb1a2b3c0800450000491c46400040114c9c08080808c0a8010a0035c82200350543123481800001000100000000076578616d706c6503636f6d0000010001c00c0001000100000e1000045db8d822";
/// TLS 1.3 `ClientHello` (SNI=example.com).
const TLS_CLIENT_HELLO: &str = "a0b1c2d3e4f53c22fb1a2b3c08004500014d1c464000400625d8c0a8010a5db8d822c92c01bb0000000100000001501801f60863000016030101200100011c0303000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff00200a0a130113021303c02bc02fc02cc030cca9cca8c013c014009c009d002f0035010000b30a0a000000000010000e00000b6578616d706c652e636f6d00170000ff01000100000a00080006001d00170018000b00020100002300000010000e000c02683208687474702f312e31000500050100000000000d001200100403080404010503080505010806060100120000003300260024001d0020404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f002d00020101002b0007063a3a03040303001b00030200021a1a000100";

fn pkt(h: &str) -> RawPacket {
    let data: Vec<u8> = (0..h.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&h[i..i + 2], 16).unwrap())
        .collect();
    RawPacket {
        ts: SystemTime::UNIX_EPOCH,
        orig_len: u32::try_from(data.len()).unwrap(),
        data,
        ifindex: 1,
    }
}

fn bench(c: &mut Criterion) {
    let reg = Registry::default();
    for (name, h) in [
        ("tcp_syn", TCP_SYN),
        ("dns_response", DNS_RESPONSE),
        ("tls_client_hello", TLS_CLIENT_HELLO),
    ] {
        let p = pkt(h);
        c.bench_function(name, |b| b.iter(|| reg.dissect(black_box(&p))));
    }
}

criterion_group!(benches, bench);
criterion_main!(benches);
