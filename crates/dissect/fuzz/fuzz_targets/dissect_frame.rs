//! `cargo +nightly fuzz run dissect_frame` (crates/dissect içinden).
#![no_main]

use std::time::SystemTime;

use libfuzzer_sys::fuzz_target;
use pakiz_dissect::{RawPacket, Registry};

fuzz_target!(|data: &[u8]| {
    let reg = Registry::default();
    let pkt = RawPacket {
        ts: SystemTime::UNIX_EPOCH,
        data: data.to_vec(),
        orig_len: u32::try_from(data.len()).unwrap_or(u32::MAX),
        ifindex: 0,
    };
    let d = reg.dissect(&pkt);
    let _ = d.summary.info.len();
});
