//! İkon seti: `unicode` (varsayılan), `nerd` (Nerd Font) ve `ascii`.

use pakiz_flow::AnalysisFlags;

/// Kullanılacak glif ailesi (`[general] icons`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum IconSet {
    #[default]
    Unicode,
    Nerd,
    Ascii,
}

impl IconSet {
    /// Config adları.
    pub const NAMES: [&'static str; 3] = ["unicode", "nerd", "ascii"];

    /// Ada göre (büyük/küçük harf duyarsız).
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        match name.to_ascii_lowercase().as_str() {
            "unicode" => Some(Self::Unicode),
            "nerd" => Some(Self::Nerd),
            "ascii" => Some(Self::Ascii),
            _ => None,
        }
    }

    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Unicode => "unicode",
            Self::Nerd => "nerd",
            Self::Ascii => "ascii",
        }
    }

    fn pick(self, unicode: &'static str, nerd: &'static str, ascii: &'static str) -> &'static str {
        match self {
            Self::Unicode => unicode,
            Self::Nerd => nerd,
            Self::Ascii => ascii,
        }
    }

    /// ASCII dışı glif kullanılıyor mu.
    #[must_use]
    pub fn is_ascii(self) -> bool {
        self == Self::Ascii
    }

    /// Üst çubuk logosu.
    #[must_use]
    pub fn logo(self) -> &'static str {
        self.pick("◆ ", "\u{f1e0} ", "")
    }

    /// Canlı yakalama rozeti simgesi (ASCII'de boş: düz metin).
    #[must_use]
    pub fn live(self) -> &'static str {
        self.pick("● ", "\u{f111} ", "")
    }

    #[must_use]
    pub fn paused(self) -> &'static str {
        self.pick("❚❚ ", "\u{f04c} ", "")
    }

    #[must_use]
    pub fn file(self) -> &'static str {
        self.pick("▤ ", "\u{f15b} ", "")
    }

    /// Paket listesi analiz sütunu: uyarı.
    #[must_use]
    pub fn warn(self) -> &'static str {
        self.pick("⚠", "\u{f071}", "!")
    }

    #[must_use]
    pub fn reset(self) -> &'static str {
        self.pick("✖", "\u{f00d}", "X")
    }

    #[must_use]
    pub fn window(self) -> &'static str {
        self.pick("⊘", "\u{f04c}", "W")
    }

    /// Satır solundaki protokol vurgu çubuğu.
    #[must_use]
    pub fn bar(self) -> &'static str {
        self.pick("▌", "▌", "|")
    }

    #[must_use]
    pub fn open(self) -> &'static str {
        self.pick("▾", "▾", "v")
    }

    #[must_use]
    pub fn closed(self) -> &'static str {
        self.pick("▸", "▸", ">")
    }

    /// Ağaç kılavuzları: (orta dal, son dal, devam, boş).
    #[must_use]
    pub fn guides(self) -> [&'static str; 4] {
        match self {
            Self::Ascii => ["|- ", "`- ", "|  ", "   "],
            _ => ["├─ ", "└─ ", "│  ", "   "],
        }
    }

    /// Kaydırma çubuğu: (iz, tutamaç).
    #[must_use]
    pub fn scroll(self) -> (&'static str, &'static str) {
        match self {
            Self::Ascii => ("|", "#"),
            _ => ("│", "┃"),
        }
    }

    /// Durum çubuğu bölüm ayırıcısı.
    #[must_use]
    pub fn separator(self) -> &'static str {
        self.pick("▌", "\u{e0b0}", "|")
    }

    #[must_use]
    pub fn ellipsis(self) -> &'static str {
        self.pick("…", "…", "...")
    }

    /// Dönen bekleme göstergesi karesi.
    #[must_use]
    pub fn spinner(self, tick: u64) -> &'static str {
        const U: [&str; 8] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧"];
        const A: [&str; 4] = ["|", "/", "-", "\\"];
        let i = usize::try_from(tick).unwrap_or(0);
        match self {
            Self::Ascii => A[i % A.len()],
            _ => U[i % U.len()],
        }
    }

    /// Başlık simgeleri.
    #[must_use]
    pub fn title_packets(self) -> &'static str {
        self.pick("☰ ", "\u{f0c9} ", "")
    }

    #[must_use]
    pub fn title_tree(self) -> &'static str {
        self.pick("⌥ ", "\u{f0e8} ", "")
    }

    #[must_use]
    pub fn title_hex(self) -> &'static str {
        self.pick("# ", "\u{f121} ", "")
    }

    /// Analiz bayrağı → sütun simgesi (öncelik: kötü TCP > pencere > RST).
    #[must_use]
    pub fn flag(self, f: AnalysisFlags) -> &'static str {
        let window = AnalysisFlags::ZERO_WINDOW.bits()
            | AnalysisFlags::ZERO_WINDOW_PROBE.bits()
            | AnalysisFlags::WINDOW_FULL.bits()
            | AnalysisFlags::RST.bits();
        if f.bits() & !window != 0 {
            self.warn()
        } else if f.bits() & window & !AnalysisFlags::RST.bits() != 0 {
            self.window()
        } else if f.contains(AnalysisFlags::RST) {
            self.reset()
        } else {
            " "
        }
    }
}
