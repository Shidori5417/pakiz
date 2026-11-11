//! Renk teması ve protokol renk kuralları.

use pakiz_flow::AnalysisFlags;
use ratatui::style::{Color, Style};

/// TUI renkleri (Aşama 9'da config'ten yüklenecek).
#[derive(Debug, Clone)]
pub struct Theme {
    pub tcp: Color,
    pub udp: Color,
    pub arp: Color,
    pub icmp: Color,
    pub dns: Color,
    pub http: Color,
    pub malformed: Color,
    pub other: Color,
    pub selected_bg: Color,
    pub hex_highlight_bg: Color,
    pub border: Color,
    pub border_focus: Color,
    pub status_bg: Color,
    pub filter_ok_bg: Color,
    pub filter_err_bg: Color,
    /// Follow Stream: istemci → sunucu verisi.
    pub follow_client: Color,
    /// Follow Stream: sunucu → istemci verisi.
    pub follow_server: Color,
    /// Kötü TCP (retransmission, dup ACK, kayıp segment...): Wireshark gibi siyah zemin kırmızı yazı.
    pub bad_tcp_fg: Color,
    pub bad_tcp_bg: Color,
    /// TCP RST.
    pub rst_fg: Color,
    pub rst_bg: Color,
    /// Sıfır/dolu pencere.
    pub window_fg: Color,
    pub window_bg: Color,
}

impl Default for Theme {
    fn default() -> Self {
        Self {
            tcp: Color::Rgb(0xd7, 0xaf, 0xff),
            udp: Color::Rgb(0x87, 0xd7, 0xff),
            arp: Color::Yellow,
            icmp: Color::Rgb(0xff, 0xaf, 0xd7),
            dns: Color::Rgb(0x87, 0xff, 0xaf),
            http: Color::Green,
            malformed: Color::Red,
            other: Color::Reset,
            selected_bg: Color::DarkGray,
            hex_highlight_bg: Color::Blue,
            border: Color::Gray,
            border_focus: Color::Cyan,
            status_bg: Color::Rgb(0x30, 0x30, 0x40),
            filter_ok_bg: Color::Rgb(0x1f, 0x5f, 0x1f),
            filter_err_bg: Color::Rgb(0x7f, 0x1f, 0x1f),
            follow_client: Color::Rgb(0xff, 0x6b, 0x6b),
            follow_server: Color::Rgb(0x6b, 0x9b, 0xff),
            bad_tcp_fg: Color::Rgb(0xff, 0x5f, 0x5f),
            bad_tcp_bg: Color::Black,
            rst_fg: Color::Rgb(0xff, 0xfc, 0x9c),
            rst_bg: Color::Rgb(0xa4, 0x00, 0x00),
            window_fg: Color::Black,
            window_bg: Color::Rgb(0xff, 0xd7, 0x5f),
        }
    }
}

impl Theme {
    /// Protokol adına (büyük/küçük harf duyarsız) göre satır rengi.
    #[must_use]
    pub fn protocol_color(&self, protocol: &str, malformed: bool) -> Color {
        if malformed {
            return self.malformed;
        }
        match protocol.to_ascii_lowercase().as_str() {
            "tcp" => self.tcp,
            "udp" => self.udp,
            "arp" => self.arp,
            "icmp" | "icmpv6" => self.icmp,
            "dns" | "mdns" => self.dns,
            "http" | "https" | "tls" => self.http,
            _ => self.other,
        }
    }

    /// Analiz bayraklı satırın özel stili (yoksa `None`). Öncelik: kötü TCP >
    /// pencere (sıfır/dolu) > RST.
    #[must_use]
    pub fn analysis_style(&self, f: AnalysisFlags) -> Option<Style> {
        let window = AnalysisFlags::ZERO_WINDOW.bits()
            | AnalysisFlags::ZERO_WINDOW_PROBE.bits()
            | AnalysisFlags::WINDOW_FULL.bits()
            | AnalysisFlags::RST.bits();
        if f.bits() & !window != 0 {
            Some(Style::default().fg(self.bad_tcp_fg).bg(self.bad_tcp_bg))
        } else if f.bits() & window & !AnalysisFlags::RST.bits() != 0 {
            Some(Style::default().fg(self.window_fg).bg(self.window_bg))
        } else if f.contains(AnalysisFlags::RST) {
            Some(Style::default().fg(self.rst_fg).bg(self.rst_bg))
        } else {
            None
        }
    }
}
