//! `cargo bench -p pakiz-flow`: 10k segmentlik tek TCP akışının işlenmesi.

#![allow(clippy::unwrap_used, clippy::many_single_char_names)]

#[path = "../tests/common/mod.rs"]
mod common;

use std::hint::black_box;

use common::{raw, sa, tcp_frame, Tcp, ACK, SYN};
use criterion::{criterion_group, criterion_main, Criterion};
use pakiz_dissect::{Dissection, RawPacket, Registry};
use pakiz_flow::FlowTable;

fn packets() -> Vec<(RawPacket, Dissection)> {
    let reg = Registry::default();
    let (c, s) = (sa("10.0.0.1:40000"), sa("10.0.0.2:9000"));
    let mut v = Vec::new();
    let mut push = |src, dst, t: &Tcp, i: u64| {
        let p = raw(tcp_frame(src, dst, t), i);
        let d = reg.dissect(&p);
        v.push((p, d));
    };
    push(c, s, &Tcp::new(100, 0, SYN, &[]), 0);
    push(s, c, &Tcp::new(500, 101, SYN | ACK, &[]), 1);
    let payload = [0x41u8; 1000];
    for i in 0..10_000u32 {
        // Her 16 segmentte bir yer değiştir (sıra dışı teslim).
        let k = if i % 16 == 0 && i + 1 < 10_000 {
            i + 1
        } else if i % 16 == 1 {
            i - 1
        } else {
            i
        };
        let seq = 101u32.wrapping_add(k * 1000);
        push(c, s, &Tcp::new(seq, 501, ACK, &payload), u64::from(i) + 2);
    }
    v
}

fn bench(c: &mut Criterion) {
    let pk = packets();
    c.bench_function("tcp_10k_segments", |b| {
        b.iter(|| {
            let mut t = FlowTable::new();
            for (i, (p, d)) in pk.iter().enumerate() {
                black_box(t.process(i as u64, p, d));
            }
            t
        });
    });
}

criterion_group!(benches, bench);
criterion_main!(benches);
