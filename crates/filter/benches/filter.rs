//! Display filter benchmark'ı: derleme ve tek paket değerlendirme.
#![allow(missing_docs, clippy::unwrap_used)]

use std::hint::black_box;
use std::time::SystemTime;

use criterion::{criterion_group, criterion_main, Criterion};
use pakiz_dissect::{RawPacket, Registry};
use pakiz_filter::{FieldCatalog, Filter};

const SYNACK: &str = "02000000000202000000000108004500003c1c46400040060a740a0000010a00000201bbc8220000000000000001a012ffff00000000020405b40402080a000000010000000201030307";
const SRC: &str =
    "(tcp.port == 443 || udp.port == 53) && ip.addr == 10.0.0.0/8 && !arp && tcp.flags.syn == 1";

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn bench(c: &mut Criterion) {
    let data = hex(SYNACK);
    let pkt = RawPacket {
        ts: SystemTime::UNIX_EPOCH,
        orig_len: u32::try_from(data.len()).unwrap(),
        data,
        ifindex: 1,
    };
    let d = Registry::default().dissect(&pkt);
    let cat = FieldCatalog::default();
    let f = Filter::compile(SRC, &cat).unwrap();
    assert!(f.matches(&d, &pkt));
    c.bench_function("compile", |b| {
        b.iter(|| Filter::compile(black_box(SRC), &cat).unwrap());
    });
    c.bench_function("matches", |b| b.iter(|| f.matches(black_box(&d), &pkt)));
}

criterion_group!(benches, bench);
criterion_main!(benches);
