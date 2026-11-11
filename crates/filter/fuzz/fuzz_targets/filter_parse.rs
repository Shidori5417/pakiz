//! `cargo +nightly fuzz run filter_parse` (crates/filter içinden).
//!
//! Girdi hem display filter hem yakalama (BPF) filtresi olarak derlenir; derlenen
//! filtreler girdinin kendisinden kurulan bir paket üzerinde çalıştırılır.
#![no_main]

use std::sync::OnceLock;
use std::time::SystemTime;

use libfuzzer_sys::fuzz_target;
use pakiz_dissect::{RawPacket, Registry};
use pakiz_filter::{bpf, complete, FieldCatalog, Filter};

fn env() -> &'static (Registry, FieldCatalog) {
    static ENV: OnceLock<(Registry, FieldCatalog)> = OnceLock::new();
    ENV.get_or_init(|| {
        let reg = Registry::default();
        let cat = FieldCatalog::new(reg.all_fields());
        (reg, cat)
    })
}

fuzz_target!(|data: &[u8]| {
    let Ok(src) = std::str::from_utf8(data) else {
        return;
    };
    let (reg, cat) = env();
    let pkt = RawPacket {
        ts: SystemTime::UNIX_EPOCH,
        data: data.to_vec(),
        orig_len: u32::try_from(data.len()).unwrap_or(u32::MAX),
        ifindex: 0,
    };
    if let Ok(prog) = bpf::compile(src) {
        let _ = bpf::run(&prog, data);
    }
    match Filter::compile(src, cat) {
        Ok(f) => {
            let d = reg.dissect(&pkt);
            let _ = f.matches(&d, &pkt);
        }
        Err(e) => {
            // Hata konumu kaynak içinde olmalı (CLI bunu dilimler).
            assert!(e.span.start <= e.span.end && e.span.end <= src.len());
        }
    }
    let _ = complete(src, cat);
});
