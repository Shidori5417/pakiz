//! pakiz-tui: ratatui + crossterm arayüzü (paket listesi / katman ağacı / hex,
//! Follow Stream, konuşmalar, istatistik) ve ortak paket işleme hattı ([`Analyzer`]).

#![cfg_attr(test, allow(clippy::unwrap_used))]

mod analyzer;
mod app;
mod keymap;
mod source;
mod store;
mod theme;
mod tree;
mod ui;
mod views;

use std::io::{self, Stdout};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use ratatui::backend::CrosstermBackend;
use ratatui::crossterm::event::{
    self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEventKind,
};
use ratatui::crossterm::execute;
use ratatui::crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::style::{Modifier, Style};
use ratatui::widgets::{Block, Borders, List, ListState};
use ratatui::Terminal;

pub use analyzer::{catalog, Analyzed, Analyzer};
pub use app::{
    App, Completion, FilterState, InputKind, InputLine, Panel, ANALYZE_BATCH, DRAIN_BATCH,
    FILTER_BATCH, INDEX_BATCH,
};
pub use keymap::{format_key, parse_key, Action, Key, Keymap};
pub use source::{PacketSource, VecSource};
pub use store::{Entry, PacketStore};
pub use theme::{format_color, parse_color, ColorRule, Theme};
pub use tree::{flatten, highlight_range, TreeRow};
pub use ui::{draw, hex_line};
pub use views::{fmt_bytes, ConvSort, ConvView, FollowMode, FollowView, StatsTab, StatsView, View};

/// Çizimler arası en kısa süre (~30 fps).
pub const FRAME: Duration = Duration::from_millis(33);

/// Terminali hazırlar; drop edilince (ve panic'te) geri yükler.
pub struct Tui {
    pub terminal: Terminal<CrosstermBackend<Stdout>>,
    /// Çizimler arası en kısa süre ([`Tui::set_fps`]).
    frame: Duration,
}

fn restore_terminal() {
    // Geri yükleme en iyi çabadır; hata durumunda yapılacak başka bir şey yok.
    let _ = disable_raw_mode();
    let _ = execute!(io::stdout(), LeaveAlternateScreen, DisableMouseCapture);
}

impl Tui {
    /// Ham mod, alternatif ekran ve fare yakalamayı açar, panic hook'u kurar.
    ///
    /// # Errors
    /// Terminal hazırlanamazsa.
    pub fn new() -> io::Result<Self> {
        let prev = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            restore_terminal();
            prev(info);
        }));
        enable_raw_mode()?;
        if let Err(e) = execute!(io::stdout(), EnterAlternateScreen, EnableMouseCapture) {
            restore_terminal();
            return Err(e);
        }
        match Terminal::new(CrosstermBackend::new(io::stdout())) {
            Ok(terminal) => Ok(Self {
                terminal,
                frame: FRAME,
            }),
            Err(e) => {
                restore_terminal();
                Err(e)
            }
        }
    }

    /// Saniyedeki en fazla çizim (1..=240'a kırpılır).
    pub fn set_fps(&mut self, fps: u32) {
        self.frame = Duration::from_secs(1) / fps.clamp(1, 240);
    }

    /// Arayüz seçim listesi. `Enter` seçer, `q`/`Esc` iptal (`None`).
    ///
    /// # Errors
    /// Terminal G/Ç hatasında.
    pub fn pick_interface(&mut self, items: &[String]) -> io::Result<Option<usize>> {
        let mut state = ListState::default().with_selected((!items.is_empty()).then_some(0));
        loop {
            self.terminal.draw(|f| {
                let list = List::new(items.iter().map(String::as_str))
                    .block(
                        Block::default()
                            .borders(Borders::ALL)
                            .title(" Arayüz seç (j/k, Enter, q) "),
                    )
                    .highlight_style(Style::default().add_modifier(Modifier::REVERSED))
                    .highlight_symbol("▶ ");
                f.render_stateful_widget(list, f.area(), &mut state);
            })?;
            if let Event::Key(k) = event::read()? {
                if k.kind == KeyEventKind::Release {
                    continue;
                }
                match k.code {
                    KeyCode::Char('j') | KeyCode::Down => state.select_next(),
                    KeyCode::Char('k') | KeyCode::Up => state.select_previous(),
                    KeyCode::Enter => {
                        return Ok(state.selected().filter(|&i| i < items.len()));
                    }
                    KeyCode::Char('q') | KeyCode::Esc => return Ok(None),
                    _ => {}
                }
            }
        }
    }

    /// Olay döngüsü: kanalı boşalt, olayları işle, en fazla `fps` (varsayılan 30) çiz.
    ///
    /// # Errors
    /// Terminal G/Ç hatasında.
    pub fn run(&mut self, app: &mut App) -> io::Result<()> {
        let frame = self.frame;
        let mut dirty = true;
        let mut last_draw = Instant::now()
            .checked_sub(frame)
            .unwrap_or_else(Instant::now);
        let mut last_status = Instant::now();
        // SIGTERM/SIGHUP: döngüden temiz çık ki `Drop` terminali geri yüklesin.
        let term = Arc::new(AtomicBool::new(false));
        for sig in [signal_hook::consts::SIGTERM, signal_hook::consts::SIGHUP] {
            signal_hook::flag::register(sig, Arc::clone(&term))?;
        }
        while !app.quit {
            if term.load(Ordering::Relaxed) {
                break;
            }
            dirty |= app.ingest();
            if last_status.elapsed() >= Duration::from_secs(1) {
                // Düşen paket sayacı gibi kaynak istatistikleri için.
                dirty = true;
                last_status = Instant::now();
            }
            if dirty && last_draw.elapsed() >= frame {
                self.terminal.draw(|f| ui::draw(f, app))?;
                last_draw = Instant::now();
                dirty = false;
            }
            let timeout = if dirty {
                frame.saturating_sub(last_draw.elapsed())
            } else {
                frame
            };
            if event::poll(timeout)? {
                // Birikmiş tüm olayları işle.
                loop {
                    match event::read()? {
                        Event::Key(k) => app.on_key(k),
                        Event::Mouse(m) => app.on_mouse(m),
                        _ => {}
                    }
                    dirty = true;
                    if !event::poll(Duration::ZERO)? {
                        break;
                    }
                }
            }
        }
        Ok(())
    }
}

impl Drop for Tui {
    fn drop(&mut self) {
        restore_terminal();
        let _ = self.terminal.show_cursor();
    }
}

#[cfg(test)]
mod tests;
