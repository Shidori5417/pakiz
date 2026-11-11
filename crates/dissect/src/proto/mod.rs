//! Yerleşik protokoller.
//!
//! Yeni protokol eklemek: `src/proto/<ad>.rs` yaz, aşağıya `mod <ad>;` ve
//! `builtin()` listesine tek satır ekle.

mod arp;
mod dhcp;
mod dns;
mod eth;
mod http;
mod icmp;
mod icmpv6;
mod ipv4;
mod ipv6;
mod mqtt;
mod ntp;
mod quic;
mod ssh;
mod tcp;
mod tls;
mod udp;
mod util;
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
        // Uygulama katmanı: port tabanlılar önce, içerik sezgisi kullananlar (TLS, HTTP) sonra.
        Box::new(dns::Dns),
        Box::new(dns::DnsTcp),
        Box::new(dns::Mdns),
        Box::new(dhcp::Dhcp),
        Box::new(ntp::Ntp),
        Box::new(quic::Quic),
        Box::new(ssh::Ssh),
        Box::new(mqtt::Mqtt),
        Box::new(tls::Tls),
        Box::new(http::Http),
    ]
}

#[cfg(test)]
mod tests {
    use crate::testutil::{hex, pkt};
    use crate::Registry;

    /// Gerçek örnek paketlerin rastgele bayt bozulmalarıyla panic'siz dissect'i
    /// (cargo-fuzz olmadan da çalışan hafif mutasyon testi).
    #[test]
    fn mutation_smoke() {
        let samples = [
            super::dns::tests::QUERY,
            super::dns::tests::RESPONSE,
            super::dns::tests::RICH,
            super::dns::tests::TCP_QUERY,
            super::dns::tests::MDNS,
            super::dhcp::tests::DISCOVER,
            super::dhcp::tests::OFFER,
            super::http::tests::GET,
            super::http::tests::RESP,
            super::tls::tests::CLIENT_HELLO,
            super::tls::tests::SERVER_HELLO,
            super::quic::tests::INITIAL,
            super::ssh::tests::KEXINIT,
            super::mqtt::tests::CONNECT,
            super::mqtt::tests::MULTI,
            super::ntp::tests::SERVER,
        ];
        let reg = Registry::default();
        let mut x: u64 = 0x9e37_79b9_7f4a_7c15;
        let mut next = move || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        for s in samples {
            let base = hex(s);
            for _ in 0..500 {
                let mut d = base.clone();
                // Ethernet/IP/L4 başlıklarını koru (54 bayt), uygulama yükünü boz.
                for _ in 0..=(next() % 8) {
                    let i = 42 + usize::try_from(next()).unwrap() % (d.len() - 42);
                    d[i] = u8::try_from(next() & 0xff).unwrap();
                }
                let _ = reg.dissect(&pkt(d));
            }
        }
    }
}
