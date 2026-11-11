#![allow(dead_code, clippy::unwrap_used)]

use std::time::SystemTime;

use pakiz_dissect::{Dissection, RawPacket, Registry};

// 10.0.0.1:443 → 10.0.0.2:51234 SYN-ACK, eth 02..01 → 02..02, ttl 64.
pub const SYNACK: &str = "02000000000202000000000108004500003c1c46400040060a740a0000010a00000201bbc8220000000000000001a012ffff00000000020405b40402080a000000010000000201030307";
// 192.168.1.10:5353 → 224.0.0.251:5353 UDP, yük 01020304.
pub const MDNS: &str =
    "01005e0000fb0200000000010800450000201c464000ff11bcd8c0a8010ae00000fb14e914e9000c000001020304";
// ARP who-has 10.0.0.1 tell 10.0.0.2.
pub const ARP: &str = "ffffffffffff000c29aabbcc08060001080006040001000c29aabbcc0a0000020000000000000a000001000000000000000000000000000000";
// QinQ: vlan 100 + vlan 200, içte 10.1.1.1 → 10.1.1.2 UDP 5353.
pub const QINQ: &str = "02000000000202000000000188a80064810060c80800450000201c464000401108830a0101010a01010214e914e9000c000001020304";
// fe80::1 → fe80::2 ICMPv6 echo.
pub const V6: &str = "02000000000202000000000186dd6000000000120040fe800000000000000000000000000001fe8000000000000000000000000000023a0001040000000080000000123400016869";
// 127.0.0.1 → 127.0.0.1 ICMP echo, yük "abcdefgh".
pub const ICMP: &str = "0000000000000000000000000800450000241c464000400120917f0000017f00000108006668000100016162636465666768";

pub fn hex(s: &str) -> Vec<u8> {
    let s: String = s.split_whitespace().collect();
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

pub fn pkt(h: &str) -> (Dissection, RawPacket) {
    let data = hex(h);
    let p = RawPacket {
        ts: SystemTime::UNIX_EPOCH,
        orig_len: u32::try_from(data.len()).unwrap(),
        data,
        ifindex: 1,
    };
    (Registry::default().dissect(&p), p)
}
