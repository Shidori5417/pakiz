//! Tuş → `Action` eşlemesi.

use std::collections::HashMap;

use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

/// Kullanıcı eylemleri.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Action {
    Down,
    Up,
    Top,
    Bottom,
    HalfPageDown,
    HalfPageUp,
    NextPanel,
    Toggle,
    Collapse,
    Expand,
    Quit,
    Pause,
    AutoScroll,
    Help,
    Filter,
    Command,
    /// Seçili paketin akışını izle (Follow Stream).
    Follow,
    /// Konuşmalar görünümü.
    Conversations,
    /// İstatistik görünümü.
    Statistics,
    /// Görünümden ana listeye dön.
    Back,
    /// Kaynak/Hedef için DNS ad çözümleme aç/kapa.
    ToggleResolve,
    /// Follow: ASCII / Hex / Raw.
    CycleMode,
    /// Konuşmalar: sıralama sütununu değiştir.
    Sort,
    /// İstatistik: alt sekme (0 tabanlı).
    SelectTab(u8),
    /// Odaklı paneli büyüt / geri al.
    Zoom,
    /// Dikey ↔ yatay düzen.
    ToggleLayout,
    /// Odaklı paneli büyüt (panel oranı).
    Grow,
    /// Odaklı paneli küçült (panel oranı).
    Shrink,
}

impl Action {
    /// Config'teki (`[keys]`) adlarıyla tüm eylemler, yardım sırasıyla.
    pub const ALL: [(&'static str, Action); 31] = [
        ("down", Action::Down),
        ("up", Action::Up),
        ("top", Action::Top),
        ("bottom", Action::Bottom),
        ("half_page_down", Action::HalfPageDown),
        ("half_page_up", Action::HalfPageUp),
        ("next_panel", Action::NextPanel),
        ("toggle", Action::Toggle),
        ("collapse", Action::Collapse),
        ("expand", Action::Expand),
        ("quit", Action::Quit),
        ("pause", Action::Pause),
        ("autoscroll", Action::AutoScroll),
        ("help", Action::Help),
        ("filter", Action::Filter),
        ("command", Action::Command),
        ("follow", Action::Follow),
        ("conversations", Action::Conversations),
        ("statistics", Action::Statistics),
        ("back", Action::Back),
        ("toggle_resolve", Action::ToggleResolve),
        ("cycle_mode", Action::CycleMode),
        ("sort", Action::Sort),
        ("tab1", Action::SelectTab(0)),
        ("tab2", Action::SelectTab(1)),
        ("tab3", Action::SelectTab(2)),
        ("tab4", Action::SelectTab(3)),
        ("zoom", Action::Zoom),
        ("toggle_layout", Action::ToggleLayout),
        ("grow", Action::Grow),
        ("shrink", Action::Shrink),
    ];

    /// Config adından eylem (`"half_page_down"` → [`Action::HalfPageDown`]).
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.iter().find(|(n, _)| *n == name).map(|&(_, a)| a)
    }

    /// Eylemin config adı.
    #[must_use]
    pub fn name(self) -> &'static str {
        Self::ALL
            .iter()
            .find(|(_, a)| *a == self)
            .map_or("?", |(n, _)| n)
    }
}

/// Tek tuş: kod + değiştiriciler.
pub type Key = (KeyCode, KeyModifiers);

const NAMED: &[(&str, KeyCode)] = &[
    ("Enter", KeyCode::Enter),
    ("Esc", KeyCode::Esc),
    ("Tab", KeyCode::Tab),
    ("BackTab", KeyCode::BackTab),
    ("Backspace", KeyCode::Backspace),
    ("Delete", KeyCode::Delete),
    ("Insert", KeyCode::Insert),
    ("Up", KeyCode::Up),
    ("Down", KeyCode::Down),
    ("Left", KeyCode::Left),
    ("Right", KeyCode::Right),
    ("Home", KeyCode::Home),
    ("End", KeyCode::End),
    ("PageUp", KeyCode::PageUp),
    ("PageDown", KeyCode::PageDown),
    ("Space", KeyCode::Char(' ')),
];

/// Tuş metnini çözer: `"j"`, `"G"`, `"Ctrl-c"`, `"Alt-x"`, `"Shift-Tab"`, `"F5"`,
/// `"PageDown"`, `"Space"`. Önekler (`Ctrl-`, `Alt-`, `Shift-`) birleştirilebilir;
/// adlar büyük/küçük harf duyarsızdır. Harflerde `Shift-x` = `X`.
///
/// # Errors
/// Bilinmeyen tuş adı veya boş metin.
pub fn parse_key(s: &str) -> Result<Key, String> {
    let mut mods = KeyModifiers::NONE;
    let mut rest = s;
    loop {
        let lower = rest.to_ascii_lowercase();
        let (m, n) = if lower.starts_with("ctrl-") && rest.len() > 5 {
            (KeyModifiers::CONTROL, 5)
        } else if lower.starts_with("alt-") && rest.len() > 4 {
            (KeyModifiers::ALT, 4)
        } else if lower.starts_with("shift-") && rest.len() > 6 {
            (KeyModifiers::SHIFT, 6)
        } else {
            break;
        };
        mods |= m;
        rest = &rest[n..];
    }
    let mut chars = rest.chars();
    let code = match (chars.next(), chars.next()) {
        (None, _) => return Err(format!("boş tuş: {s:?}")),
        (Some(c), None) => KeyCode::Char(c),
        _ => {
            if let Some(&(_, k)) = NAMED.iter().find(|(n, _)| n.eq_ignore_ascii_case(rest)) {
                k
            } else if let Some(n) = rest
                .strip_prefix(['F', 'f'])
                .and_then(|n| n.parse::<u8>().ok())
                .filter(|n| (1..=24).contains(n))
            {
                KeyCode::F(n)
            } else {
                return Err(format!(
                    "bilinmeyen tuş: {s:?} (ör. \"j\", \"Ctrl-d\", \"Alt-x\", \"Enter\", \"PageDown\", \"F1\")"
                ));
            }
        }
    };
    Ok(normalize(code, mods))
}

/// Karakter tuşlarında Shift karakterin kendisine yansır (`G`); eşlemede
/// Shift değiştiricisi bu yüzden yok sayılır. `Shift-Tab` → `BackTab`.
fn normalize(code: KeyCode, mods: KeyModifiers) -> Key {
    match code {
        KeyCode::Char(c) if mods.contains(KeyModifiers::SHIFT) => (
            KeyCode::Char(c.to_ascii_uppercase()),
            mods - KeyModifiers::SHIFT,
        ),
        KeyCode::Tab if mods.contains(KeyModifiers::SHIFT) => {
            (KeyCode::BackTab, mods - KeyModifiers::SHIFT)
        }
        KeyCode::BackTab => (code, mods - KeyModifiers::SHIFT),
        _ => (code, mods),
    }
}

/// [`parse_key`] ile geri okunabilir metin.
#[must_use]
pub fn format_key((code, mods): Key) -> String {
    let mut s = String::new();
    if mods.contains(KeyModifiers::CONTROL) {
        s.push_str("Ctrl-");
    }
    if mods.contains(KeyModifiers::ALT) {
        s.push_str("Alt-");
    }
    if mods.contains(KeyModifiers::SHIFT) {
        s.push_str("Shift-");
    }
    match code {
        KeyCode::Char(' ') => s.push_str("Space"),
        KeyCode::Char(c) => s.push(c),
        KeyCode::F(n) => {
            s.push('F');
            s.push_str(&n.to_string());
        }
        other => match NAMED.iter().find(|(_, k)| *k == other) {
            Some((n, _)) => s.push_str(n),
            None => s.push('?'),
        },
    }
    s
}

/// Tuş eşlem tablosu; varsayılanların üstüne config'teki `[keys]` uygulanır.
#[derive(Debug, Clone)]
pub struct Keymap {
    map: HashMap<Key, Action>,
}

impl Default for Keymap {
    fn default() -> Self {
        use Action as A;
        use KeyCode as K;
        let n = KeyModifiers::NONE;
        let c = KeyModifiers::CONTROL;
        let map = [
            ((K::Char('j'), n), A::Down),
            ((K::Down, n), A::Down),
            ((K::Char('k'), n), A::Up),
            ((K::Up, n), A::Up),
            ((K::Char('g'), n), A::Top),
            ((K::Home, n), A::Top),
            ((K::Char('G'), n), A::Bottom),
            ((K::End, n), A::Bottom),
            ((K::Char('d'), c), A::HalfPageDown),
            ((K::PageDown, n), A::HalfPageDown),
            ((K::Char('u'), c), A::HalfPageUp),
            ((K::PageUp, n), A::HalfPageUp),
            ((K::Tab, n), A::NextPanel),
            ((K::Enter, n), A::Toggle),
            ((K::Char(' '), n), A::Toggle),
            ((K::Char('h'), n), A::Collapse),
            ((K::Left, n), A::Collapse),
            ((K::Char('l'), n), A::Expand),
            ((K::Right, n), A::Expand),
            ((K::Char('q'), n), A::Quit),
            ((K::Char('c'), c), A::Quit),
            ((K::Char('p'), n), A::Pause),
            ((K::Char('a'), n), A::AutoScroll),
            ((K::Char('?'), n), A::Help),
            ((K::Char('/'), n), A::Filter),
            ((K::Char(':'), n), A::Command),
            ((K::Char('F'), n), A::Follow),
            ((K::Char('c'), n), A::Conversations),
            ((K::Char('S'), n), A::Statistics),
            ((K::Esc, n), A::Back),
            ((K::Char('n'), n), A::ToggleResolve),
            ((K::Char('m'), n), A::CycleMode),
            ((K::Char('s'), n), A::Sort),
            ((K::Char('1'), n), A::SelectTab(0)),
            ((K::Char('2'), n), A::SelectTab(1)),
            ((K::Char('3'), n), A::SelectTab(2)),
            ((K::Char('4'), n), A::SelectTab(3)),
            ((K::Char('z'), n), A::Zoom),
            ((K::Char('L'), n), A::ToggleLayout),
            ((K::Char('+'), n), A::Grow),
            ((K::Char('-'), n), A::Shrink),
        ]
        .into_iter()
        .collect();
        Self { map }
    }
}

impl Keymap {
    #[must_use]
    pub fn action(&self, key: &KeyEvent) -> Option<Action> {
        self.map.get(&normalize(key.code, key.modifiers)).copied()
    }

    pub fn bind(&mut self, code: KeyCode, mods: KeyModifiers, action: Action) {
        self.map.insert(normalize(code, mods), action);
    }

    /// Eylemin tüm tuşlarını `keys` ile değiştirir. Bu tuşlar başka bir eyleme
    /// bağlıysa o bağ kalkar; kaldırılan `(tuş, eski eylem)` çiftleri döner.
    pub fn set(&mut self, action: Action, keys: &[Key]) -> Vec<(Key, Action)> {
        self.map.retain(|_, a| *a != action);
        let mut stolen = Vec::new();
        for &(code, mods) in keys {
            let k = normalize(code, mods);
            if let Some(old) = self.map.insert(k, action) {
                if old != action {
                    stolen.push((k, old));
                }
            }
        }
        stolen
    }

    /// Eyleme bağlı tuşlar (kararlı sırada).
    #[must_use]
    pub fn keys_for(&self, action: Action) -> Vec<Key> {
        let mut v: Vec<Key> = self
            .map
            .iter()
            .filter(|(_, a)| **a == action)
            .map(|(k, _)| *k)
            .collect();
        v.sort_by_key(|k| (k.1.bits(), format_key(*k)));
        v
    }
}
