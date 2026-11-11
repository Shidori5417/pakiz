//! Renk teması ve renklendirme kuralları (Wireshark "coloring rules" gibi).

use pakiz_dissect::{Dissection, RawPacket};
use pakiz_filter::{FieldCatalog, Filter, FilterError};
use pakiz_flow::AnalysisFlags;
use ratatui::style::{Color, Style};

/// TUI renkleri. Yerleşik: [`Theme::dark`] (varsayılan) ve [`Theme::light`].
#[derive(Debug, Clone)]
pub struct Theme {
    /// Genel zemin / yazı rengi (`Reset` = terminalin kendi rengi).
    pub bg: Color,
    pub fg: Color,
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
        Self::dark()
    }
}

impl Theme {
    /// Yerleşik tema adları.
    pub const NAMES: [&'static str; 2] = ["dark", "light"];

    /// Ada göre yerleşik tema (büyük/küçük harf duyarsız).
    #[must_use]
    pub fn by_name(name: &str) -> Option<Self> {
        match name.to_ascii_lowercase().as_str() {
            "dark" => Some(Self::dark()),
            "light" => Some(Self::light()),
            _ => None,
        }
    }

    /// Koyu terminaller için (varsayılan).
    #[must_use]
    pub fn dark() -> Self {
        Self {
            bg: Color::Reset,
            fg: Color::Reset,
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

    /// Açık zemin (beyaz) için koyu tonlar.
    #[must_use]
    pub fn light() -> Self {
        Self {
            bg: Color::Rgb(0xfa, 0xfa, 0xfa),
            fg: Color::Rgb(0x20, 0x20, 0x20),
            tcp: Color::Rgb(0x6a, 0x1b, 0x9a),
            udp: Color::Rgb(0x00, 0x5f, 0x9e),
            arp: Color::Rgb(0x8a, 0x6d, 0x00),
            icmp: Color::Rgb(0xad, 0x14, 0x57),
            dns: Color::Rgb(0x1b, 0x7a, 0x3d),
            http: Color::Rgb(0x2e, 0x7d, 0x32),
            malformed: Color::Rgb(0xc6, 0x28, 0x28),
            other: Color::Rgb(0x20, 0x20, 0x20),
            selected_bg: Color::Rgb(0xc8, 0xd8, 0xf0),
            hex_highlight_bg: Color::Rgb(0xff, 0xe0, 0x82),
            border: Color::Rgb(0x90, 0x90, 0x90),
            border_focus: Color::Rgb(0x00, 0x60, 0xc0),
            status_bg: Color::Rgb(0xe0, 0xe0, 0xe8),
            filter_ok_bg: Color::Rgb(0xc8, 0xf0, 0xc8),
            filter_err_bg: Color::Rgb(0xf8, 0xc8, 0xc8),
            follow_client: Color::Rgb(0xb0, 0x00, 0x00),
            follow_server: Color::Rgb(0x00, 0x30, 0xb0),
            bad_tcp_fg: Color::Rgb(0xff, 0x5f, 0x5f),
            bad_tcp_bg: Color::Black,
            rst_fg: Color::Rgb(0xff, 0xfc, 0x9c),
            rst_bg: Color::Rgb(0xa4, 0x00, 0x00),
            window_fg: Color::Black,
            window_bg: Color::Rgb(0xff, 0xd7, 0x5f),
        }
    }

    /// Varsayılan renklendirme kuralları (sırayla, ilk eşleşen): yerleşik
    /// analiz/protokol renklerine denk. Kaynak, ön plan, arka plan.
    #[must_use]
    pub fn default_coloring(&self) -> Vec<(&'static str, Option<Color>, Option<Color>)> {
        vec![
            (BAD_TCP, Some(self.bad_tcp_fg), Some(self.bad_tcp_bg)),
            (WINDOW, Some(self.window_fg), Some(self.window_bg)),
            ("tcp.flags.reset == 1", Some(self.rst_fg), Some(self.rst_bg)),
            ("arp", Some(self.arp), None),
            ("icmp or icmpv6", Some(self.icmp), None),
            ("dns or mdns", Some(self.dns), None),
            ("http or tls", Some(self.http), None),
            ("tcp", Some(self.tcp), None),
            ("udp", Some(self.udp), None),
        ]
    }

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

const BAD_TCP: &str = "tcp.analysis.retransmission or tcp.analysis.fast_retransmission \
or tcp.analysis.spurious_retransmission or tcp.analysis.out_of_order \
or tcp.analysis.duplicate_ack or tcp.analysis.keep_alive or tcp.analysis.lost_segment \
or tcp.analysis.ack_lost_segment";
const WINDOW: &str =
    "tcp.analysis.zero_window or tcp.analysis.zero_window_probe or tcp.analysis.window_full";

/// Derlenmiş renklendirme kuralı: display filter eşleşirse satıra `fg`/`bg`.
#[derive(Debug)]
pub struct ColorRule {
    pub source: String,
    filter: Filter,
    pub fg: Option<Color>,
    pub bg: Option<Color>,
}

impl ColorRule {
    /// # Errors
    /// Filtre derlenemezse.
    pub fn new(
        source: &str,
        catalog: &FieldCatalog,
        fg: Option<Color>,
        bg: Option<Color>,
    ) -> Result<Self, FilterError> {
        Ok(Self {
            source: source.to_owned(),
            filter: Filter::compile(source, catalog)?,
            fg,
            bg,
        })
    }

    #[must_use]
    pub fn matches(&self, d: &Dissection, raw: &RawPacket) -> bool {
        self.filter.matches(d, raw)
    }

    #[must_use]
    pub fn style(&self) -> Style {
        let mut st = Style::default();
        if let Some(c) = self.fg {
            st = st.fg(c);
        }
        if let Some(c) = self.bg {
            st = st.bg(c);
        }
        st
    }

    /// Temanın varsayılan kuralları (derlenmiş).
    ///
    /// # Errors
    /// Yerleşik bir kural derlenemezse (olmamalı; testle korunur).
    pub fn defaults(theme: &Theme, catalog: &FieldCatalog) -> Result<Vec<Self>, FilterError> {
        theme
            .default_coloring()
            .into_iter()
            .map(|(src, fg, bg)| Self::new(src, catalog, fg, bg))
            .collect()
    }
}

/// Renk metni: `"#c8a2ff"`, `"red"`, `"darkgray"`, `"reset"`, `"42"` (256 renk indeksi).
///
/// # Errors
/// Tanınmayan renk.
pub fn parse_color(s: &str) -> Result<Color, String> {
    s.parse::<Color>()
        .map_err(|_| format!("geçersiz renk: {s:?} (ör. \"#c8a2ff\", \"red\", \"reset\")"))
}

/// [`parse_color`] ile geri okunabilir metin.
#[must_use]
pub fn format_color(c: Color) -> String {
    match c {
        Color::Rgb(r, g, b) => format!("#{r:02x}{g:02x}{b:02x}"),
        Color::Indexed(i) => i.to_string(),
        other => format!("{other:?}").to_ascii_lowercase(),
    }
}
