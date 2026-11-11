//! Renk teması ve protokol renk kuralları.

use ratatui::style::Color;

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
}
