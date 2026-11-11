//! pakiz-tui: ratatui + crossterm arayüzü (paket listesi / katman ağacı / hex).

#![cfg_attr(test, allow(clippy::unwrap_used))]

mod app;
mod keymap;
mod source;
mod store;
mod theme;
mod tree;
mod ui;

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

pub use app::{App, InputKind, InputLine, Panel, DRAIN_BATCH, INDEX_BATCH};
pub use keymap::{Action, Keymap};
pub use source::{PacketSource, VecSource};
pub use store::{Entry, PacketStore};
pub use theme::Theme;
pub use tree::{flatten, highlight_range, TreeRow};
pub use ui::{draw, hex_line};

/// Çizimler arası en kısa süre (~30 fps).
pub const FRAME: Duration = Duration::from_millis(33);

/// Terminali hazırlar; drop edilince (ve panic'te) geri yükler.
pub struct Tui {
    pub terminal: Terminal<CrosstermBackend<Stdout>>,
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
            Ok(terminal) => Ok(Self { terminal }),
            Err(e) => {
                restore_terminal();
                Err(e)
            }
        }
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

    /// Olay döngüsü: kanalı boşalt, olayları işle, en fazla ~30 fps çiz.
    ///
    /// # Errors
    /// Terminal G/Ç hatasında.
    pub fn run(&mut self, app: &mut App) -> io::Result<()> {
        let mut dirty = true;
        let mut last_draw = Instant::now()
            .checked_sub(FRAME)
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
            if dirty && last_draw.elapsed() >= FRAME {
                self.terminal.draw(|f| ui::draw(f, app))?;
                last_draw = Instant::now();
                dirty = false;
            }
            let timeout = if dirty {
                FRAME.saturating_sub(last_draw.elapsed())
            } else {
                FRAME
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
