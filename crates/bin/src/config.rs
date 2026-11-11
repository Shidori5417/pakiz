//! Yapılandırma dosyası: `$XDG_CONFIG_HOME/pakiz/config.toml`
//! (yoksa `~/.config/pakiz/config.toml`). Dosya yoksa varsayılanlar kullanılır;
//! CLI bayrakları dosyadaki değerleri ezer.

use std::collections::{BTreeMap, HashMap};
use std::fmt::Write as _;
use std::ops::Range;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use pakiz_tui::{
    catalog, format_color, format_key, parse_color, parse_key, Action, ColorRule, IconSet, Key,
    Keymap, PacketStore, Theme,
};
use ratatui::style::Color;
use serde::Deserialize;
use toml::Spanned;

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct FileCfg {
    general: General,
    theme: ThemeCfg,
    keys: KeysCfg,
    coloring: Vec<ColoringCfg>,
}

/// `[general]`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct General {
    /// `-i` verilmezse yakalanacak arayüz.
    pub default_interface: Option<String>,
    /// Bellekte tutulacak en fazla paket (halka tampon).
    pub max_packets: usize,
    /// Saniyedeki en fazla çizim.
    pub fps: u32,
    /// Kaynak/Hedef yerine DNS adları.
    pub resolve_names: bool,
    /// Canlı yakalamada yeni paketlere otomatik kaydır.
    pub autoscroll: bool,
    /// Simge ailesi: `unicode` | `nerd` | `ascii`.
    pub icons: String,
}

impl Default for General {
    fn default() -> Self {
        Self {
            default_interface: None,
            max_packets: PacketStore::DEFAULT_MAX,
            fps: 30,
            resolve_names: false,
            autoscroll: true,
            icons: IconSet::default().name().to_owned(),
        }
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct ThemeCfg {
    name: Option<Spanned<String>>,
    bg: Option<Spanned<String>>,
    fg: Option<Spanned<String>>,
    selection: Option<Spanned<String>>,
    selection_fg: Option<Spanned<String>>,
    accent: Option<Spanned<String>>,
    highlight: Option<Spanned<String>>,
    status: Option<Spanned<String>>,
    border: Option<Spanned<String>>,
    border_focus: Option<Spanned<String>>,
    protocols: BTreeMap<String, Spanned<String>>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ColoringCfg {
    filter: Spanned<String>,
    fg: Option<Spanned<String>>,
    bg: Option<Spanned<String>>,
}

/// Çözülmüş ayarlar.
pub struct Settings {
    pub general: General,
    /// `general.icons` çözülmüş hali.
    pub icons: IconSet,
    pub theme: Theme,
    pub keymap: Keymap,
    /// Config'teki `[[coloring]]` kuralları (temanın varsayılanlarından önce denenir).
    pub coloring: Vec<ColorRule>,
}

const PROTOCOLS: [&str; 8] = [
    "tcp",
    "udp",
    "arp",
    "icmp",
    "dns",
    "http",
    "malformed",
    "other",
];

fn protocol_slot<'a>(t: &'a mut Theme, name: &str) -> Option<&'a mut Color> {
    Some(match name {
        "tcp" => &mut t.tcp,
        "udp" => &mut t.udp,
        "arp" => &mut t.arp,
        "icmp" => &mut t.icmp,
        "dns" => &mut t.dns,
        "http" => &mut t.http,
        "malformed" => &mut t.malformed,
        "other" => &mut t.other,
        _ => return None,
    })
}

/// Varsayılan config yolu: `$XDG_CONFIG_HOME/pakiz/config.toml`, yoksa
/// `$HOME/.config/pakiz/config.toml`.
#[must_use]
pub fn default_path() -> Option<PathBuf> {
    let xdg = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute());
    let base = xdg.or_else(|| {
        std::env::var_os("HOME")
            .map(PathBuf::from)
            .filter(|p| p.is_absolute())
            .map(|h| h.join(".config"))
    })?;
    Some(base.join("pakiz").join("config.toml"))
}

/// Config'i yükler. `explicit` (`--config`) verilmişse dosya bulunmalıdır;
/// varsayılan yoldaki dosya yoksa varsayılanlar döner. `theme` (`--theme`)
/// dosyadaki tema adını ezer.
///
/// # Errors
/// Okuma hatası veya geçersiz içerik (dosya:satır:sütun ile).
pub fn load(explicit: Option<&Path>, theme: Option<&str>) -> Result<Settings> {
    let path = match explicit {
        Some(p) => Some(p.to_path_buf()),
        None => default_path().filter(|p| p.exists()),
    };
    let Some(path) = path else {
        return parse("", "<varsayılan>", theme);
    };
    let text = std::fs::read_to_string(&path)
        .with_context(|| format!("config okunamadı: {}", path.display()))?;
    parse(&text, &path.display().to_string(), theme)
}

/// `name:satır:sütun: mesaj` + kaynak satırı ve `^` işareti.
fn located(name: &str, text: &str, span: Option<Range<usize>>, msg: &str) -> anyhow::Error {
    let Some(span) = span else {
        return anyhow!("{name}: {msg}");
    };
    let start = span.start.min(text.len());
    let before = text.get(..start).unwrap_or("");
    let line = before.matches('\n').count() + 1;
    let line_start = before.rfind('\n').map_or(0, |i| i + 1);
    let col = before.get(line_start..).map_or(0, |s| s.chars().count());
    let src = text
        .get(line_start..)
        .and_then(|s| s.lines().next())
        .unwrap_or("");
    let width = text
        .get(start..span.end.min(text.len()))
        .and_then(|s| s.lines().next())
        .map_or(1, |s| s.chars().count().max(1));
    anyhow!(
        "{name}:{line}:{}: {msg}\n  {src}\n  {}{}",
        col + 1,
        " ".repeat(col),
        "^".repeat(width)
    )
}

fn color(name: &str, text: &str, v: &Spanned<String>) -> Result<Color> {
    parse_color(v.get_ref()).map_err(|e| located(name, text, Some(v.span()), &e))
}

fn opt_color(name: &str, text: &str, v: Option<&Spanned<String>>) -> Result<Option<Color>> {
    v.map(|v| color(name, text, v)).transpose()
}

/// Config metnini çözer (`name` hata mesajlarında dosya adı olarak geçer).
///
/// # Errors
/// TOML sözdizimi, bilinmeyen alan, geçersiz renk/tuş/eylem/filtre.
pub fn parse(text: &str, name: &str, theme_override: Option<&str>) -> Result<Settings> {
    let cfg: FileCfg = toml::from_str(text).map_err(|e| {
        located(
            name,
            text,
            e.span(),
            &format!("geçersiz config: {}", e.message().trim()),
        )
    })?;
    let g = &cfg.general;
    if !(1..=240).contains(&g.fps) {
        return Err(anyhow!("{name}: general.fps 1..=240 olmalı ({})", g.fps));
    }
    if g.max_packets == 0 {
        return Err(anyhow!("{name}: general.max_packets en az 1 olmalı"));
    }

    let icons = IconSet::from_name(&g.icons).ok_or_else(|| {
        anyhow!(
            "{name}: general.icons bilinmiyor: {:?} (geçerli: {})",
            g.icons,
            IconSet::NAMES.join(", ")
        )
    })?;
    let theme = build_theme(&cfg.theme, name, text, theme_override)?;
    let keymap = build_keys(&cfg.keys, name, text)?;
    let coloring = build_coloring(&cfg.coloring, name, text)?;
    Ok(Settings {
        general: cfg.general,
        icons,
        theme,
        keymap,
        coloring,
    })
}

/// Tema: `--theme` > `[theme].name` > dark; renk geçişleri üstüne yazılır.
fn build_theme(
    t: &ThemeCfg,
    name: &str,
    text: &str,
    theme_override: Option<&str>,
) -> Result<Theme> {
    let mut theme = match (theme_override, &t.name) {
        (Some(t), _) => Theme::by_name(t).ok_or_else(|| {
            anyhow!(
                "bilinmeyen tema: {t:?} (yerleşik: {})",
                Theme::NAMES.join(", ")
            )
        })?,
        (None, Some(n)) => Theme::by_name(n.get_ref()).ok_or_else(|| {
            located(
                name,
                text,
                Some(n.span()),
                &format!("bilinmeyen tema (yerleşik: {})", Theme::NAMES.join(", ")),
            )
        })?,
        (None, None) => Theme::default(),
    };
    for (slot, v) in [
        (&mut theme.bg, &t.bg),
        (&mut theme.fg, &t.fg),
        (&mut theme.selected_bg, &t.selection),
        (&mut theme.selected_fg, &t.selection_fg),
        (&mut theme.accent, &t.accent),
        (&mut theme.hex_highlight_bg, &t.highlight),
        (&mut theme.status_bg, &t.status),
        (&mut theme.border, &t.border),
        (&mut theme.border_focus, &t.border_focus),
    ] {
        if let Some(c) = opt_color(name, text, v.as_ref())? {
            *slot = c;
        }
    }
    for (proto, v) in &t.protocols {
        let c = color(name, text, v)?;
        let slot = protocol_slot(&mut theme, proto).ok_or_else(|| {
            located(
                name,
                text,
                Some(v.span()),
                &format!(
                    "bilinmeyen protokol rengi: {proto:?} (geçerli: {})",
                    PROTOCOLS.join(", ")
                ),
            )
        })?;
        *slot = c;
    }

    Ok(theme)
}

type KeysCfg = BTreeMap<String, Spanned<Vec<Spanned<String>>>>;

/// Tuşlar: her eylemin tuş listesi varsayılanın yerini alır.
fn build_keys(cfg: &KeysCfg, name: &str, text: &str) -> Result<Keymap> {
    let mut keymap = Keymap::default();
    let mut seen: HashMap<Key, &str> = HashMap::new();
    for (action, keys) in cfg {
        let a = Action::from_name(action).ok_or_else(|| {
            let names: Vec<&str> = Action::ALL.iter().map(|(n, _)| *n).collect();
            located(
                name,
                text,
                Some(keys.span()),
                &format!(
                    "bilinmeyen eylem: {action:?} (geçerli: {})",
                    names.join(", ")
                ),
            )
        })?;
        let mut parsed = Vec::new();
        for k in keys.get_ref() {
            let key =
                parse_key(k.get_ref()).map_err(|e| located(name, text, Some(k.span()), &e))?;
            if let Some(other) = seen.insert(key, action) {
                if other != action.as_str() {
                    return Err(located(
                        name,
                        text,
                        Some(k.span()),
                        &format!(
                            "tuş çakışması: {:?} hem {other:?} hem {action:?} eylemine atanmış",
                            k.get_ref()
                        ),
                    ));
                }
            }
            parsed.push(key);
        }
        keymap.set(a, &parsed);
    }

    Ok(keymap)
}

fn build_coloring(cfg: &[ColoringCfg], name: &str, text: &str) -> Result<Vec<ColorRule>> {
    let cat = catalog();
    let mut coloring = Vec::new();
    for r in cfg {
        let fg = opt_color(name, text, r.fg.as_ref())?;
        let bg = opt_color(name, text, r.bg.as_ref())?;
        let src = r.filter.get_ref();
        let rule = ColorRule::new(src, &cat, fg, bg).map_err(|e| {
            // Filtre içindeki konumu dosyadaki konuma çevir (tırnak sonrası).
            let base = r.filter.span().start + 1;
            let span = (base + e.span.start)..(base + e.span.end.max(e.span.start + 1));
            located(
                name,
                text,
                Some(span),
                &format!("renklendirme filtresi hatası: {}", e.msg),
            )
        })?;
        coloring.push(rule);
    }
    Ok(coloring)
}

fn quote(s: &str) -> String {
    toml::Value::String(s.to_owned()).to_string()
}

/// Varsayılan config (`--dump-config`): yorumlu ve tekrar okunabilir.
#[must_use]
pub fn dump() -> String {
    let g = General::default();
    let t = Theme::dark();
    let km = Keymap::default();
    let mut s = String::new();
    let _ = writeln!(
        s,
        "# pakiz yapılandırması: $XDG_CONFIG_HOME/pakiz/config.toml (yoksa ~/.config/pakiz/config.toml)\n\
         # `pakiz --dump-config > ~/.config/pakiz/config.toml` ile oluşturulabilir.\n\
         # Komut satırı bayrakları (-i, --max-packets, -n, --theme) buradaki değerleri ezer.\n\
         \n\
         [general]\n\
         # -i verilmezse yakalanacak arayüz (yoksa TUI arayüz seçtirir).\n\
         # default_interface = \"eth0\"\n\
         # Bellekte tutulacak en fazla paket (canlı yakalama; eskiler düşer).\n\
         max_packets = {}\n\
         # Saniyedeki en fazla çizim (1..=240).\n\
         fps = {}\n\
         # IP yerine DNS cevaplarından öğrenilen adları göster (TUI'de `n`).\n\
         resolve_names = {}\n\
         # Canlı yakalamada yeni paketlere otomatik kaydır (TUI'de `a`).\n\
         autoscroll = {}\n\
         # Simge ailesi: {}. `nerd` Nerd Font gerektirir; `ascii` yalnızca düz karakter kullanır.\n\
         icons = \"{}\"\n\
         \n\
         [theme]\n\
         # Yerleşik temalar: {}. Aşağıdaki renkler temanın üstüne yazılır.\n\
         # Renk: \"#rrggbb\", ad (red, green, darkgray, reset...) veya 256 renk indeksi.\n\
         name = \"dark\"",
        g.max_packets,
        g.fps,
        g.resolve_names,
        g.autoscroll,
        IconSet::NAMES.join(" | "),
        g.icons,
        Theme::NAMES.join(", ")
    );
    for (k, c) in [
        ("bg", t.bg),
        ("fg", t.fg),
        ("selection", t.selected_bg),
        ("selection_fg", t.selected_fg),
        ("accent", t.accent),
        ("highlight", t.hex_highlight_bg),
        ("status", t.status_bg),
        ("border", t.border),
        ("border_focus", t.border_focus),
    ] {
        let _ = writeln!(s, "# {k} = {}", quote(&format_color(c)));
    }
    let _ = writeln!(
        s,
        "\n# Protokol satır renkleri (varsayılan renklendirme kuralları bunları kullanır).\n[theme.protocols]"
    );
    let mut tt = t.clone();
    for p in PROTOCOLS {
        if let Some(c) = protocol_slot(&mut tt, p) {
            let _ = writeln!(s, "# {p} = {}", quote(&format_color(*c)));
        }
    }
    let _ = writeln!(
        s,
        "\n# Eylem → tuş listesi. Bir eylem yazılırsa varsayılan tuşlarının yerini alır;\n\
         # tuş başka bir eylemin varsayılanıysa ondan alınır. Önekler: Ctrl- Alt- Shift-;\n\
         # adlı tuşlar: Enter Esc Tab BackTab Backspace Delete Insert Up Down Left Right\n\
         # Home End PageUp PageDown Space F1..F24.\n[keys]"
    );
    for (n, a) in Action::ALL {
        let keys: Vec<String> = km
            .keys_for(a)
            .into_iter()
            .map(|k| quote(&format_key(k)))
            .collect();
        let _ = writeln!(s, "{n} = [{}]", keys.join(", "));
    }
    let _ = writeln!(
        s,
        "\n# Renklendirme kuralları (Wireshark coloring rules gibi): display filter ile,\n\
         # sırayla denenir, ilk eşleşen satırın rengini belirler. Buradakiler temanın\n\
         # varsayılan kurallarından önce gelir; varsayılanlar (sırayla):"
    );
    for (src, fg, bg) in t.default_coloring() {
        let c = |c: Option<Color>| c.map_or_else(|| "-".to_owned(), format_color);
        let _ = writeln!(s, "#   {src}  (fg {}, bg {})", c(fg), c(bg));
    }
    let _ = writeln!(
        s,
        "#\n# [[coloring]]\n# filter = \"tcp.port == 22\"\n# fg = \"#000000\"\n# bg = \"#a0d0ff\""
    );
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

    #[test]
    fn empty_is_default() {
        let s = parse("", "x", None).unwrap();
        assert_eq!(s.general, General::default());
        assert_eq!(s.general.fps, 30);
        assert!(s.coloring.is_empty());
    }

    #[test]
    fn dump_roundtrips_to_defaults() {
        let s = parse(&dump(), "dump", None).unwrap();
        assert_eq!(s.general, General::default());
        let d = Keymap::default();
        for (_, a) in Action::ALL {
            assert_eq!(s.keymap.keys_for(a), d.keys_for(a), "{a:?}");
        }
        assert_eq!(s.theme.tcp, Theme::dark().tcp);
    }

    #[test]
    fn example_file_parses_and_matches_dump() {
        let ex = include_str!("../../../docs/config.example.toml");
        parse(ex, "docs/config.example.toml", None).unwrap();
        assert_eq!(
            ex,
            dump(),
            "docs/config.example.toml güncel değil: --dump-config"
        );
    }

    #[test]
    fn full_config() {
        let s = parse(
            r##"
[general]
default_interface = "wlan0"
max_packets = 1000
fps = 60
resolve_names = true
autoscroll = false

[theme]
name = "light"
bg = "black"
selection = "#112233"

[theme.protocols]
tcp = "#c8a2ff"

[keys]
down = ["x", "Down"]
filter = ["Ctrl-f"]
quit = ["q", "Ctrl-c"]

[[coloring]]
filter = "tcp.analysis.flags"
fg = "red"
bg = "black"

[[coloring]]
filter = "udp.port == 53"
fg = "#00ff00"
"##,
            "t",
            None,
        )
        .unwrap();
        assert_eq!(s.general.default_interface.as_deref(), Some("wlan0"));
        assert_eq!((s.general.fps, s.general.max_packets), (60, 1000));
        assert!(s.general.resolve_names && !s.general.autoscroll);
        assert_eq!(s.theme.bg, Color::Black);
        assert_eq!(s.theme.selected_bg, Color::Rgb(0x11, 0x22, 0x33));
        assert_eq!(s.theme.tcp, Color::Rgb(0xc8, 0xa2, 0xff));
        assert_eq!(s.theme.udp, Theme::light().udp);
        let k = |c| s.keymap.action(&KeyEvent::new(c, KeyModifiers::NONE));
        assert_eq!(k(KeyCode::Char('x')), Some(Action::Down));
        assert_eq!(k(KeyCode::Char('j')), None);
        assert_eq!(k(KeyCode::Char('/')), None);
        assert_eq!(
            s.keymap
                .action(&KeyEvent::new(KeyCode::Char('f'), KeyModifiers::CONTROL)),
            Some(Action::Filter)
        );
        assert_eq!(s.coloring.len(), 2);
        assert_eq!(s.coloring[1].bg, None);
        // --theme dosyadakini ezer.
        let s = parse("[theme]\nname = \"light\"", "t", Some("dark")).unwrap();
        assert_eq!(s.theme.tcp, Theme::dark().tcp);
    }

    #[test]
    fn icons_and_new_themes() {
        assert_eq!(parse("", "x", None).unwrap().icons, IconSet::Unicode);
        let s = parse("[general]\nicons = \"nerd\"\n", "x", None).unwrap();
        assert_eq!((s.icons, s.general.icons.as_str()), (IconSet::Nerd, "nerd"));
        assert_eq!(
            parse("[general]\nicons = \"ASCII\"\n", "x", None)
                .unwrap()
                .icons,
            IconSet::Ascii
        );
        let e = parse("[general]\nicons = \"emoji\"\n", "c.toml", None)
            .err()
            .unwrap()
            .to_string();
        assert!(
            e.contains("general.icons") && e.contains("unicode, nerd, ascii"),
            "{e}"
        );
        for (name, accent) in [
            ("ocean", Theme::ocean().accent),
            ("forest", Theme::forest().accent),
        ] {
            let s = parse(&format!("[theme]\nname = \"{name}\"\n"), "x", None).unwrap();
            assert_eq!(s.theme.accent, accent, "{name}");
        }
        assert_eq!(
            parse("", "x", Some("ocean")).unwrap().theme.bg,
            Theme::ocean().bg
        );
        let s = parse(
            "[theme]\naccent = \"#ff00ff\"\nselection_fg = \"black\"\n",
            "x",
            None,
        )
        .unwrap();
        assert_eq!(s.theme.accent, Color::Rgb(255, 0, 255));
        assert_eq!(s.theme.selected_fg, Color::Black);
        // Yeni eylemler config'ten değiştirilebilir.
        let s = parse("[keys]\nzoom = [\"Z\"]\ngrow = [\"=\"]\n", "x", None).unwrap();
        let k = |c| s.keymap.action(&KeyEvent::new(c, KeyModifiers::NONE));
        assert_eq!(k(KeyCode::Char('Z')), Some(Action::Zoom));
        assert_eq!(k(KeyCode::Char('z')), None);
        assert_eq!(k(KeyCode::Char('=')), Some(Action::Grow));
        assert_eq!(k(KeyCode::Char('L')), Some(Action::ToggleLayout));
        assert_eq!(k(KeyCode::Char('-')), Some(Action::Shrink));
    }

    fn err(text: &str) -> String {
        match parse(text, "c.toml", None) {
            Ok(_) => panic!("hata bekleniyordu: {text}"),
            Err(e) => e.to_string(),
        }
    }

    #[test]
    fn errors_are_located() {
        let e = err("[general]\nfps = \"çok\"\n");
        assert!(e.starts_with("c.toml:2:7: geçersiz config"), "{e}");
        assert!(e.contains('^'), "{e}");
        let e = err("[general]\nfoo = 1\n");
        assert!(e.starts_with("c.toml:2:1:") && e.contains("foo"), "{e}");
        let e = err("[general\n");
        assert!(e.starts_with("c.toml:1:"), "{e}");
        let e = err("[theme]\nname = \"mor\"\n");
        assert!(e.starts_with("c.toml:2:8: bilinmeyen tema"), "{e}");
        let e = err("[theme]\nfg = \"#12\"\n");
        assert!(e.starts_with("c.toml:2:6: geçersiz renk"), "{e}");
        let e = err("[theme.protocols]\nsctp = \"red\"\n");
        assert!(e.contains("bilinmeyen protokol rengi"), "{e}");
        let e = err("[keys]\nzipla = [\"j\"]\n");
        assert!(
            e.starts_with("c.toml:2:") && e.contains("bilinmeyen eylem"),
            "{e}"
        );
        let e = err("[keys]\ndown = [\"Ctrl-\"]\n");
        assert!(e.starts_with("c.toml:2:9: bilinmeyen tuş"), "{e}");
        let e = err("[keys]\ndown = [\"x\"]\nup = [\"x\"]\n");
        assert!(e.starts_with("c.toml:3:7: tuş çakışması"), "{e}");
        let e = err("[[coloring]]\nfilter = \"tcp.port ==\"\n");
        assert!(
            e.starts_with("c.toml:2:") && e.contains("renklendirme filtresi"),
            "{e}"
        );
        let e = err("[general]\nfps = 0\n");
        assert!(e.contains("general.fps"), "{e}");
        assert!(parse("", "x", Some("neon")).is_err());
    }

    #[test]
    fn explicit_missing_file_fails() {
        assert!(load(Some(Path::new("/yok/pakiz.toml")), None).is_err());
    }
}
