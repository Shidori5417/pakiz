//! Yerleşik protokoller.
//!
//! Yeni protokol eklemek: `src/proto/<ad>.rs` yaz, aşağıya `mod <ad>;` ve
//! `builtin()` listesine tek satır ekle.

mod arp;
mod eth;
mod icmp;
mod icmpv6;
mod ipv4;
mod ipv6;
mod tcp;
mod udp;
mod vlan;

use crate::Dissector;

/// Tüm yerleşik dissector'lar (kayıt sırası = eşleşme önceliği).
#[must_use]
pub fn builtin() -> Vec<Box<dyn Dissector>> {
    vec![
        Box::new(eth::Ethernet),
        Box::new(vlan::Vlan),
        Box::new(arp::Arp),
        Box::new(ipv4::Ipv4),
        Box::new(ipv6::Ipv6),
        Box::new(icmp::Icmp),
        Box::new(icmpv6::Icmpv6),
        Box::new(tcp::Tcp),
        Box::new(udp::Udp),
    ]
}
