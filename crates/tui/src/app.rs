//! Uygulama durumu ve eylemler (render'dan bağımsız).

use std::collections::{HashSet, VecDeque};

use pakiz_dissect::{Dissection, RawPacket, Registry};
use pakiz_filter::{complete, FieldCatalog, Filter, FilterError};
use ratatui::crossterm::event::{
    KeyCode, KeyEvent, KeyEventKind, MouseButton, MouseEvent, MouseEventKind,
};
use ratatui::layout::{Position, Rect};

use crate::keymap::{Action, Keymap};
use crate::source::{PacketSource, VecSource};
use crate::store::PacketStore;
use crate::theme::Theme;
use crate::tree::{flatten, NodePath, TreeRow};

/// Tek seferde kaynaktan çekilecek en fazla paket.
pub const DRAIN_BATCH: usize = 50_000;

/// Dosya modunda her tick'te indekslenecek en fazla paket.
pub const INDEX_BATCH: usize = 20_000;

/// Filtre değiştikten sonra her tick'te yeniden değerlendirilecek en fazla paket.
pub const FILTER_BATCH: usize = 5_000;

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

/// Filtre giriş satırının canlı doğrulama durumu.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FilterState {
    Empty,
    Valid,
    Invalid(FilterError),
}

/// Alt giriş satırı (`/` filtre, `:` komut). İmleç her zaman sondadır.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InputLine {
    pub kind: InputKind,
    pub text: String,
    /// Yalnızca filtre satırında anlamlı.
    pub state: FilterState,
}

/// Tab ile otomatik tamamlama durumu (birden çok aday varken).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Completion {
    /// Tamamlanan kelimenin metindeki bayt başlangıcı.
    pub start: usize,
    pub candidates: Vec<&'static str>,
    /// Tab döngüsünde seçili aday.
    pub index: Option<usize>,
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
    pub completion: Option<Completion>,
    /// Uygulanan filtre metni (boş = filtre yok).
    pub filter_text: String,
    pub catalog: FieldCatalog,
    filter: Option<Filter>,
    /// Filtreyi geçen paketlerin numaraları (artan). Seçim/liste bu sıraya göredir.
    shown: VecDeque<u64>,
    /// Henüz filtreden geçirilmemiş ilk paket numarası.
    scan_next: u64,
    history: Vec<String>,
    history_pos: Option<usize>,
    pub command_text: String,
    pub quit: bool,
    /// Gösterilen listede (filtre sonrası) seçili konum.
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
    /// Durum çubuğunda gösterilen son komut sonucu.
    pub message: Option<String>,
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
            completion: None,
            filter_text: String::new(),
            catalog: FieldCatalog::default(),
            filter: None,
            shown: VecDeque::new(),
            scan_next: 1,
            history: Vec::new(),
            history_pos: None,
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
            message: None,
        }
    }

    /// Dosya kaynağı: paketler belleğe alınmaz, indeks artımlı olarak [`App::ingest`]
    /// içinde ilerletilir.
    #[must_use]
    pub fn from_file(file: pakiz_storage::IndexedFile, name: impl Into<String>) -> Self {
        let src = VecSource {
            name: name.into(),
            packets: VecDeque::new(),
        };
        let mut app = Self::new(Box::new(src), 1);
        app.store = PacketStore::from_file(file);
        app.autoscroll = false;
        app
    }

    /// Filtreyi geçen paketlerin store indeksleri (sırayla).
    pub fn displayed(&self) -> impl Iterator<Item = usize> + '_ {
        let first = self.store.first_number();
        self.shown.iter().map(move |&n| index_of(n, first))
    }

    /// Gösterilen paket sayısı.
    #[must_use]
    pub fn displayed_len(&self) -> usize {
        self.shown.len()
    }

    /// Gösterilen listedeki `pos`. paketin store indeksi.
    #[must_use]
    pub fn store_index(&self, pos: usize) -> Option<usize> {
        let n = *self.shown.get(pos)?;
        Some(index_of(n, self.store.first_number()))
    }

    /// Seçili paketin store indeksi.
    #[must_use]
    pub fn selected_index(&self) -> Option<usize> {
        self.store_index(self.selected?)
    }

    /// Display filter'ı derleyip uygular (boş metin = filtre yok). Mevcut paketler
    /// [`App::ingest`] içinde tick başına [`FILTER_BATCH`] paket olarak yeniden süzülür.
    ///
    /// # Errors
    /// Derleme hatası; bu durumda eski filtre kalır.
    pub fn set_filter(&mut self, text: &str) -> Result<(), FilterError> {
        let text = text.trim();
        self.filter = if text.is_empty() {
            None
        } else {
            Some(Filter::compile(text, &self.catalog)?)
        };
        self.filter_text = text.to_string();
        self.shown.clear();
        self.scan_next = self.store.first_number();
        self.selected = None;
        self.list_offset = 0;
        Ok(())
    }

    /// Yeniden süzme sürüyorsa yüzde (0..=99).
    #[must_use]
    pub fn filter_progress(&self) -> Option<u8> {
        let first = self.store.first_number();
        let end = first + self.store.len() as u64;
        if self.filter.is_none() || self.scan_next >= end {
            return None;
        }
        let pct = (self.scan_next - first) * 100 / (end - first);
        Some(u8::try_from(pct.min(99)).unwrap_or(99))
    }

    /// Henüz süzülmemiş paketlerden en fazla `budget` tanesini değerlendirir;
    /// ilerleme olduysa `true`.
    fn scan(&mut self, budget: usize) -> bool {
        let first = self.store.first_number();
        self.scan_next = self.scan_next.max(first);
        let end = first + self.store.len() as u64;
        let budget = if self.filter.is_none() {
            usize::MAX
        } else {
            budget
        };
        let mut n = 0;
        while self.scan_next < end && n < budget {
            let num = self.scan_next;
            let keep = self.filter.as_ref().is_none_or(|f| {
                self.store.raw(index_of(num, first)).is_some_and(|raw| {
                    let d = self.registry.dissect_numbered(&raw, Some(num));
                    f.matches(&d, &raw)
                })
            });
            if keep {
                self.shown.push_back(num);
            }
            self.scan_next += 1;
            n += 1;
        }
        n > 0
    }

    /// Gösterilen paketleri `path`'e yazar (biçim uzantıdan); yazılan sayıyı döner.
    /// Dosya modunda önce indeksleme ve süzme tamamlanır.
    ///
    /// # Errors
    /// Dosya oluşturma/yazma hatası.
    pub fn export(&mut self, path: &str) -> pakiz_storage::Result<usize> {
        while self.store.index_more(INDEX_BATCH) > 0 {}
        self.scan(usize::MAX);
        let mut w = pakiz_storage::create(path, pakiz_storage::Format::from_path(path))?;
        let mut n = 0;
        for i in self.displayed() {
            if let Some(p) = self.store.raw(i) {
                w.write_packet(&p)?;
                n += 1;
            }
        }
        w.flush()?;
        Ok(n)
    }

    fn run_command(&mut self, cmd: &str) {
        let cmd = cmd.trim();
        if cmd == "q" {
            self.quit = true;
        } else if let Some(path) = cmd.strip_prefix("w ").map(str::trim) {
            self.message = Some(match self.export(path) {
                Ok(n) => format!("{n} paket yazıldı: {path}"),
                Err(e) => format!("yazılamadı: {e}"),
            });
        } else if !cmd.is_empty() {
            self.message = Some(format!("bilinmeyen komut: {cmd}"));
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
        if self.store.is_file() {
            changed |= self.store.index_more(INDEX_BATCH) > 0;
        }
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
        changed |= self.scan(FILTER_BATCH);
        if self.selected.is_none() && !self.shown.is_empty() {
            self.selected = Some(0);
        }
        if changed && self.autoscroll && !self.paused && !self.shown.is_empty() {
            self.select(self.shown.len() - 1);
        }
        changed
    }

    /// Paketi ayrıştırır, (süzme yetişmişse) filtreyi aynı ayrıştırma üzerinde
    /// uygular ve özetle birlikte saklar.
    pub(crate) fn add(&mut self, p: RawPacket) {
        let number = self.store.next_number();
        let d = self.registry.dissect_numbered(&p, Some(number));
        let in_order = self.scan_next == number;
        let keep = in_order && self.filter.as_ref().is_none_or(|f| f.matches(&d, &p));
        let malformed = d.layers.iter().any(pakiz_dissect::Layer::is_malformed);
        let evicted = self.store.push(p, d.summary, malformed) > 0;
        if in_order {
            if keep {
                self.shown.push_back(number);
            }
            self.scan_next += 1;
        }
        if evicted {
            self.trim_evicted();
        }
    }

    /// Halka tampondan düşen paketleri gösterilen listeden de çıkarır.
    fn trim_evicted(&mut self) {
        let first = self.store.first_number();
        while self.shown.front().is_some_and(|&n| n < first) {
            self.shown.pop_front();
            if let Some(s) = self.selected.as_mut() {
                *s = s.saturating_sub(1);
            }
            self.list_offset = self.list_offset.saturating_sub(1);
        }
        if self.shown.is_empty() {
            self.selected = None;
        }
        self.scan_next = self.scan_next.max(first);
    }

    fn select(&mut self, pos: usize) {
        if self.shown.is_empty() {
            return;
        }
        self.selected = Some(pos.min(self.shown.len() - 1));
    }

    /// Seçili paketin ayrıştırması ve ağaç satırları (lazy, cache'li).
    pub fn tree(&mut self) -> Option<(&Dissection, &[TreeRow])> {
        let e = self.store.get(self.selected_index()?)?;
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
        self.selected_index()
            .and_then(|i| self.store.get(i))
            .map_or(0, |e| e.raw.data.len().div_ceil(16))
    }

    /// Odaktaki paneli `delta` satır kaydırır (negatif = yukarı).
    fn move_by(&mut self, panel: Panel, delta: isize) {
        match panel {
            Panel::List => {
                if self.shown.is_empty() {
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
                if self.autoscroll && !self.shown.is_empty() {
                    self.select(self.shown.len() - 1);
                }
            }
            Action::Help => self.show_help = !self.show_help,
            Action::Filter | Action::Command => {
                let (kind, text) = if action == Action::Filter {
                    (InputKind::Filter, self.filter_text.clone())
                } else {
                    (InputKind::Command, String::new())
                };
                self.input = Some(InputLine {
                    kind,
                    text,
                    state: FilterState::Empty,
                });
                self.completion = None;
                self.history_pos = None;
                self.revalidate();
            }
        }
    }

    pub fn on_key(&mut self, key: KeyEvent) {
        if key.kind == KeyEventKind::Release {
            return;
        }
        if self.input.is_some() {
            self.on_input_key(key.code);
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

    fn on_input_key(&mut self, code: KeyCode) {
        let Some(inp) = self.input.as_mut() else {
            return;
        };
        let is_filter = inp.kind == InputKind::Filter;
        if code != KeyCode::Tab {
            self.completion = None;
        }
        match code {
            KeyCode::Esc => self.input = None,
            KeyCode::Enter => self.submit_input(),
            KeyCode::Backspace => {
                inp.text.pop();
            }
            KeyCode::Char(c) => inp.text.push(c),
            KeyCode::Tab if is_filter => self.complete_input(),
            KeyCode::Up | KeyCode::Down if is_filter && !self.history.is_empty() => {
                let last = self.history.len() - 1;
                self.history_pos = match (code, self.history_pos) {
                    (KeyCode::Up, None) => Some(last),
                    (KeyCode::Up, Some(p)) => Some(p.saturating_sub(1)),
                    (_, Some(p)) if p < last => Some(p + 1),
                    _ => None,
                };
                inp.text = self
                    .history_pos
                    .and_then(|p| self.history.get(p))
                    .cloned()
                    .unwrap_or_default();
            }
            _ => {}
        }
        self.revalidate();
    }

    fn submit_input(&mut self) {
        let Some(inp) = self.input.take() else {
            return;
        };
        match inp.kind {
            InputKind::Filter => match self.set_filter(&inp.text) {
                Ok(()) => {
                    self.message = None;
                    let t = self.filter_text.clone();
                    if !t.is_empty() && self.history.last() != Some(&t) {
                        self.history.push(t);
                    }
                }
                Err(e) => {
                    // Hatalı filtre uygulanmaz; satır açık kalır.
                    self.input = Some(InputLine {
                        state: FilterState::Invalid(e),
                        ..inp
                    });
                }
            },
            InputKind::Command => {
                self.run_command(&inp.text);
                self.command_text = inp.text;
            }
        }
    }

    /// Filtre satırını yeniden doğrular (her tuşta).
    fn revalidate(&mut self) {
        if let Some(inp) = self.input.as_mut() {
            if inp.kind == InputKind::Filter {
                inp.state = if inp.text.trim().is_empty() {
                    FilterState::Empty
                } else {
                    match pakiz_filter::validate(&inp.text, &self.catalog) {
                        Ok(()) => FilterState::Valid,
                        Err(e) => FilterState::Invalid(e),
                    }
                };
            }
        }
    }

    /// Tab: sondaki kelimeyi alan adlarıyla tamamlar. Tek aday → tamamla; çok aday →
    /// ortak önek + aday listesi; ardışık Tab adaylar arasında döner.
    fn complete_input(&mut self) {
        let Some(inp) = self.input.as_mut() else {
            return;
        };
        if let Some(c) = self.completion.as_mut() {
            let i = c.index.map_or(0, |i| (i + 1) % c.candidates.len());
            c.index = Some(i);
            inp.text.truncate(c.start);
            inp.text.push_str(c.candidates[i]);
            return;
        }
        let start = inp
            .text
            .char_indices()
            .rev()
            .find(|&(_, ch)| !(ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-')))
            .map_or(0, |(i, ch)| i + ch.len_utf8());
        let word = &inp.text[start..];
        let candidates: Vec<&'static str> = complete(word, &self.catalog)
            .iter()
            .map(|d| d.name)
            .collect();
        let Some(&first) = candidates.first() else {
            return;
        };
        let prefix = candidates.iter().fold(first, |acc, c| {
            let n = acc
                .bytes()
                .zip(c.bytes())
                .take_while(|(a, b)| a == b)
                .count();
            &acc[..n]
        });
        inp.text.truncate(start);
        inp.text.push_str(prefix);
        if candidates.len() > 1 {
            self.completion = Some(Completion {
                start,
                candidates,
                index: None,
            });
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
                            if idx < self.shown.len() {
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

/// Paket numarasını store indeksine çevirir (`n >= first`).
fn index_of(n: u64, first: u64) -> usize {
    usize::try_from(n - first).unwrap_or(usize::MAX)
}
