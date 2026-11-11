//! Uygulama durumu ve eylemler (render'dan bağımsız).

use std::collections::{HashSet, VecDeque};

use pakiz_dissect::{Dissection, RawPacket, Registry};
use ratatui::crossterm::event::{
    KeyCode, KeyEvent, KeyEventKind, MouseButton, MouseEvent, MouseEventKind,
};
use ratatui::layout::{Position, Rect};

use crate::keymap::{Action, Keymap};
use crate::source::PacketSource;
use crate::store::PacketStore;
use crate::theme::Theme;
use crate::tree::{flatten, NodePath, TreeRow};

/// Tek seferde kaynaktan çekilecek en fazla paket.
pub const DRAIN_BATCH: usize = 50_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Panel {
    List,
    Tree,
    Hex,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputKind {
    Filter,
    Command,
}

/// Alt giriş satırı (filtre Aşama 5'te bağlanacak).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InputLine {
    pub kind: InputKind,
    pub text: String,
}

/// Son çizimdeki panel alanları (fare isabeti ve sayfa boyu için).
#[derive(Debug, Clone, Copy, Default)]
pub struct Areas {
    pub list: Rect,
    pub tree: Rect,
    pub hex: Rect,
}

struct TreeCache {
    number: u64,
    dissection: Dissection,
    rows: Vec<TreeRow>,
}

#[allow(clippy::struct_excessive_bools)]
pub struct App {
    source: Box<dyn PacketSource>,
    registry: Registry,
    pub store: PacketStore,
    /// Duraklatılmışken gelen paketler (en fazla store kapasitesi kadar).
    pending: VecDeque<RawPacket>,
    pending_dropped: u64,
    pub keymap: Keymap,
    pub theme: Theme,
    pub focus: Panel,
    pub paused: bool,
    pub autoscroll: bool,
    pub show_help: bool,
    pub input: Option<InputLine>,
    /// Onaylanmış son filtre metni (henüz uygulanmıyor).
    pub filter_text: String,
    pub command_text: String,
    pub quit: bool,
    pub selected: Option<usize>,
    pub list_offset: usize,
    pub tree_selected: usize,
    pub tree_offset: usize,
    pub hex_offset: usize,
    expanded: HashSet<NodePath>,
    cache: Option<TreeCache>,
    pub areas: Areas,
    /// Hex panelinin son takip ettiği vurgu başlangıcı.
    pub(crate) last_hl: Option<usize>,
    max_pending: usize,
}

impl App {
    #[must_use]
    pub fn new(source: Box<dyn PacketSource>, max_packets: usize) -> Self {
        Self {
            source,
            registry: Registry::default(),
            store: PacketStore::new(max_packets),
            pending: VecDeque::new(),
            pending_dropped: 0,
            keymap: Keymap::default(),
            theme: Theme::default(),
            focus: Panel::List,
            paused: false,
            autoscroll: true,
            show_help: false,
            input: None,
            filter_text: String::new(),
            command_text: String::new(),
            quit: false,
            selected: None,
            list_offset: 0,
            tree_selected: 0,
            tree_offset: 0,
            hex_offset: 0,
            expanded: HashSet::new(),
            cache: None,
            areas: Areas::default(),
            last_hl: None,
            max_pending: max_packets.max(1),
        }
    }

    #[must_use]
    pub fn source_name(&self) -> &str {
        self.source.name()
    }

    /// Kaynak + halka tampon + duraklatma kuyruğunda düşen toplam.
    #[must_use]
    pub fn dropped(&self) -> u64 {
        self.source.dropped() + self.store.evicted() + self.pending_dropped
    }

    #[must_use]
    pub fn pending_len(&self) -> usize {
        self.pending.len()
    }

    /// Kaynaktan en fazla `DRAIN_BATCH` paket çeker; değişiklik olduysa `true`.
    pub fn ingest(&mut self) -> bool {
        let mut changed = false;
        if !self.paused {
            let n = self.pending.len().min(DRAIN_BATCH);
            let queued: Vec<RawPacket> = self.pending.drain(..n).collect();
            for p in queued {
                self.add(p);
                changed = true;
            }
        }
        for _ in 0..DRAIN_BATCH {
            let Some(p) = self.source.try_next() else {
                break;
            };
            changed = true;
            if self.paused {
                if self.pending.len() >= self.max_pending {
                    self.pending.pop_front();
                    self.pending_dropped += 1;
                }
                self.pending.push_back(p);
            } else {
                self.add(p);
            }
        }
        if changed && self.autoscroll && !self.paused && !self.store.is_empty() {
            self.select(self.store.len() - 1);
        }
        changed
    }

    fn add(&mut self, p: RawPacket) {
        let d = self.registry.dissect(&p);
        let malformed = d.layers.iter().any(pakiz_dissect::Layer::is_malformed);
        if self.store.push(p, d.summary, malformed) > 0 {
            if let Some(s) = self.selected.as_mut() {
                *s = s.saturating_sub(1);
            }
            self.list_offset = self.list_offset.saturating_sub(1);
        }
        if self.selected.is_none() {
            self.selected = Some(0);
        }
    }

    fn select(&mut self, idx: usize) {
        if self.store.is_empty() {
            return;
        }
        self.selected = Some(idx.min(self.store.len() - 1));
    }

    /// Seçili paketin ayrıştırması ve ağaç satırları (lazy, cache'li).
    pub fn tree(&mut self) -> Option<(&Dissection, &[TreeRow])> {
        let e = self.store.get(self.selected?)?;
        let stale = self.cache.as_ref().is_none_or(|c| c.number != e.number);
        if stale {
            let dissection = self.registry.dissect_numbered(&e.raw, Some(e.number));
            let rows = flatten(&dissection, &self.expanded);
            self.tree_selected = self.tree_selected.min(rows.len().saturating_sub(1));
            self.cache = Some(TreeCache {
                number: e.number,
                dissection,
                rows,
            });
        }
        self.cache
            .as_ref()
            .map(|c| (&c.dissection, c.rows.as_slice()))
    }

    fn reflatten(&mut self) {
        if let Some(c) = self.cache.as_mut() {
            c.rows = flatten(&c.dissection, &self.expanded);
            self.tree_selected = self.tree_selected.min(c.rows.len().saturating_sub(1));
        }
    }

    fn tree_len(&mut self) -> usize {
        self.tree().map_or(0, |(_, r)| r.len())
    }

    /// Seçili ağaç satırı (vurgu için ofset/uzunluk).
    pub fn selected_row(&mut self) -> Option<TreeRow> {
        let i = self.tree_selected;
        self.tree().and_then(|(_, r)| r.get(i).cloned())
    }

    fn page(&self, panel: Panel) -> usize {
        let a = match panel {
            Panel::List => self.areas.list,
            Panel::Tree => self.areas.tree,
            Panel::Hex => self.areas.hex,
        };
        usize::from(a.height.saturating_sub(3)).max(2) / 2
    }

    fn hex_lines(&self) -> usize {
        self.selected
            .and_then(|i| self.store.get(i))
            .map_or(0, |e| e.raw.data.len().div_ceil(16))
    }

    /// Odaktaki paneli `delta` satır kaydırır (negatif = yukarı).
    fn move_by(&mut self, panel: Panel, delta: isize) {
        match panel {
            Panel::List => {
                if self.store.is_empty() {
                    return;
                }
                let cur = self.selected.unwrap_or(0);
                if delta < 0 {
                    self.autoscroll = false;
                }
                self.select(cur.saturating_add_signed(delta));
            }
            Panel::Tree => {
                let n = self.tree_len();
                if n > 0 {
                    self.tree_selected = self.tree_selected.saturating_add_signed(delta).min(n - 1);
                }
            }
            Panel::Hex => {
                let n = self.hex_lines();
                self.hex_offset = self
                    .hex_offset
                    .saturating_add_signed(delta)
                    .min(n.saturating_sub(1));
            }
        }
    }

    fn set_expanded(&mut self, open: Option<bool>) {
        let Some(row) = self.selected_row() else {
            return;
        };
        if !row.has_children {
            return;
        }
        let want = open.unwrap_or(!row.expanded);
        if want {
            self.expanded.insert(row.path);
        } else {
            self.expanded.remove(&row.path);
        }
        self.reflatten();
    }

    pub fn apply(&mut self, action: Action) {
        let page = isize::try_from(self.page(self.focus)).unwrap_or(1);
        match action {
            Action::Down => self.move_by(self.focus, 1),
            Action::Up => self.move_by(self.focus, -1),
            Action::HalfPageDown => self.move_by(self.focus, page),
            Action::HalfPageUp => self.move_by(self.focus, -page),
            Action::Top => self.move_by(self.focus, isize::MIN),
            Action::Bottom => self.move_by(self.focus, isize::MAX),
            Action::NextPanel => {
                self.focus = match self.focus {
                    Panel::List => Panel::Tree,
                    Panel::Tree => Panel::Hex,
                    Panel::Hex => Panel::List,
                };
            }
            Action::Toggle => self.set_expanded(None),
            Action::Collapse => self.set_expanded(Some(false)),
            Action::Expand => self.set_expanded(Some(true)),
            Action::Quit => self.quit = true,
            Action::Pause => self.paused = !self.paused,
            Action::AutoScroll => {
                self.autoscroll = !self.autoscroll;
                if self.autoscroll && !self.store.is_empty() {
                    self.select(self.store.len() - 1);
                }
            }
            Action::Help => self.show_help = !self.show_help,
            Action::Filter | Action::Command => {
                let (kind, text) = if action == Action::Filter {
                    (InputKind::Filter, self.filter_text.clone())
                } else {
                    (InputKind::Command, String::new())
                };
                self.input = Some(InputLine { kind, text });
            }
        }
    }

    pub fn on_key(&mut self, key: KeyEvent) {
        if key.kind == KeyEventKind::Release {
            return;
        }
        if let Some(inp) = self.input.as_mut() {
            match key.code {
                KeyCode::Esc => self.input = None,
                KeyCode::Enter => {
                    if let Some(inp) = self.input.take() {
                        match inp.kind {
                            InputKind::Filter => self.filter_text = inp.text,
                            InputKind::Command => {
                                if inp.text.trim() == "q" {
                                    self.quit = true;
                                }
                                self.command_text = inp.text;
                            }
                        }
                    }
                }
                KeyCode::Backspace => {
                    inp.text.pop();
                }
                KeyCode::Char(c) => inp.text.push(c),
                _ => {}
            }
            return;
        }
        if self.show_help {
            if matches!(key.code, KeyCode::Esc | KeyCode::Char('?' | 'q')) {
                self.show_help = false;
            }
            return;
        }
        if let Some(a) = self.keymap.action(&key) {
            self.apply(a);
        }
    }

    fn panel_at(&self, x: u16, y: u16) -> Option<Panel> {
        let p = Position::new(x, y);
        [
            (self.areas.list, Panel::List),
            (self.areas.tree, Panel::Tree),
            (self.areas.hex, Panel::Hex),
        ]
        .into_iter()
        .find(|(r, _)| r.contains(p))
        .map(|(_, k)| k)
    }

    pub fn on_mouse(&mut self, m: MouseEvent) {
        let Some(panel) = self.panel_at(m.column, m.row) else {
            return;
        };
        match m.kind {
            MouseEventKind::ScrollDown => self.move_by(panel, 3),
            MouseEventKind::ScrollUp => self.move_by(panel, -3),
            MouseEventKind::Down(MouseButton::Left) => {
                self.focus = panel;
                match panel {
                    Panel::List => {
                        // Kenarlık + başlık satırı.
                        let top = self.areas.list.y + 2;
                        if m.row >= top {
                            let idx = self.list_offset + usize::from(m.row - top);
                            if idx < self.store.len() {
                                self.autoscroll = false;
                                self.select(idx);
                            }
                        }
                    }
                    Panel::Tree => {
                        let top = self.areas.tree.y + 1;
                        if m.row >= top {
                            let idx = self.tree_offset + usize::from(m.row - top);
                            if idx < self.tree_len() {
                                if idx == self.tree_selected {
                                    self.set_expanded(None);
                                }
                                self.tree_selected = idx;
                            }
                        }
                    }
                    Panel::Hex => {}
                }
            }
            _ => {}
        }
    }
}
