//! Paket kaynağı soyutlaması (canlı yakalama, ileride dosya).

use pakiz_dissect::RawPacket;

/// TUI'ye paket besleyen kaynak.
pub trait PacketSource {
    /// Durum çubuğunda gösterilen ad (arayüz veya dosya).
    fn name(&self) -> &str;
    /// Bekleyen bir paket varsa döner; bloklamaz.
    fn try_next(&mut self) -> Option<RawPacket>;
    /// Kaynak tarafında düşen paket (kernel + kanal).
    fn dropped(&self) -> u64 {
        0
    }
}

/// Testler ve sabit listeler için vektör kaynağı.
#[derive(Debug, Default)]
pub struct VecSource {
    pub name: String,
    pub packets: std::collections::VecDeque<RawPacket>,
}

impl PacketSource for VecSource {
    fn name(&self) -> &str {
        &self.name
    }
    fn try_next(&mut self) -> Option<RawPacket> {
        self.packets.pop_front()
    }
}
