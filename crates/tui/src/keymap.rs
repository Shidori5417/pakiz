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
}

/// Tuş eşlem tablosu (Aşama 9'da config'ten yüklenecek).
#[derive(Debug, Clone)]
pub struct Keymap {
    map: HashMap<(KeyCode, KeyModifiers), Action>,
}

impl Default for Keymap {
    fn default() -> Self {
        use Action as A;
        use KeyCode as K;
        let n = KeyModifiers::NONE;
        let c = KeyModifiers::CONTROL;
        let s = KeyModifiers::SHIFT;
        let map = [
            ((K::Char('j'), n), A::Down),
            ((K::Down, n), A::Down),
            ((K::Char('k'), n), A::Up),
            ((K::Up, n), A::Up),
            ((K::Char('g'), n), A::Top),
            ((K::Home, n), A::Top),
            ((K::Char('G'), s), A::Bottom),
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
            ((K::Char('?'), s), A::Help),
            ((K::Char('/'), n), A::Filter),
            ((K::Char(':'), n), A::Command),
            ((K::Char(':'), s), A::Command),
        ]
        .into_iter()
        .collect();
        Self { map }
    }
}

impl Keymap {
    #[must_use]
    pub fn action(&self, key: &KeyEvent) -> Option<Action> {
        self.map.get(&(key.code, key.modifiers)).copied()
    }

    pub fn bind(&mut self, code: KeyCode, mods: KeyModifiers, action: Action) {
        self.map.insert((code, mods), action);
    }
}
