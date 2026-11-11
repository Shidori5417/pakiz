//! Çizim: üç panel, giriş satırı, durum çubuğu, yardım penceresi.

use std::ops::Range;

use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Cell, Clear, Paragraph, Row, Table};
use ratatui::Frame;

use crate::app::{App, FilterState, InputKind, InputLine, Panel};
use crate::theme::Theme;
use crate::tree::highlight_range;

const HELP: &[(&str, &str)] = &[
    ("j / k, ↓ / ↑", "aşağı / yukarı"),
    ("g / G", "baş / son"),
    ("Ctrl-d / Ctrl-u", "yarım sayfa"),
    ("Tab", "panel odağı"),
    ("Enter / Space", "ağaçta aç/kapa"),
    ("h / l, ← / →", "kapa / aç"),
    ("p", "duraklat / devam"),
    ("a", "otomatik kaydırma"),
    ("/", "filtre (Tab tamamla, ↑/↓ geçmiş)"),
    (":", "komut (:q çıkış, :w dosya)"),
    ("?", "bu yardım"),
    ("q", "çıkış"),
    ("fare", "tıkla: seç, tekerlek: kaydır"),
];

fn block<'a>(title: &'a str, focused: bool, theme: &Theme) -> Block<'a> {
    let color = if focused {
        theme.border_focus
    } else {
        theme.border
    };
    let mut style = Style::default().fg(color);
    if focused {
        style = style.add_modifier(Modifier::BOLD);
    }
    Block::default()
        .borders(Borders::ALL)
        .border_style(style)
        .title(title)
}

/// `offset`'i `sel` görünür kalacak biçimde ayarlar.
fn keep_visible(offset: &mut usize, sel: usize, height: usize) {
    if height == 0 {
        return;
    }
    if sel < *offset {
        *offset = sel;
    } else if sel >= *offset + height {
        *offset = sel + 1 - height;
    }
}

/// Tüm ekranı çizer.
pub fn draw(f: &mut Frame, app: &mut App) {
    let input_h = u16::from(app.input.is_some());
    let [list, tree, hex, input, status] = Layout::vertical([
        Constraint::Percentage(45),
        Constraint::Percentage(30),
        Constraint::Min(4),
        Constraint::Length(input_h),
        Constraint::Length(1),
    ])
    .areas(f.area());
    app.areas.list = list;
    app.areas.tree = tree;
    app.areas.hex = hex;
    draw_list(f, app, list);
    draw_tree(f, app, tree);
    draw_hex(f, app, hex);
    if let Some(inp) = &app.input {
        f.render_widget(input_line(inp, &app.theme), input);
    }
    draw_status(f, app, status);
    draw_completion(f, app, input);
    if app.show_help {
        draw_help(f, &app.theme);
    }
}

/// Giriş satırı. Filtrede arka plan geçerliyse yeşil, hatalıysa kırmızı; hata
/// aralığının altı çizilir.
fn input_line<'a>(inp: &'a InputLine, theme: &Theme) -> Paragraph<'a> {
    let prefix = match inp.kind {
        InputKind::Filter => "/",
        InputKind::Command => ":",
    };
    let t = inp.text.as_str();
    let mut spans = vec![Span::raw(prefix)];
    let mut bg = Style::default();
    let mut cursor = Span::raw("█");
    if inp.kind == InputKind::Filter {
        match &inp.state {
            FilterState::Empty => {}
            FilterState::Valid => bg = bg.bg(theme.filter_ok_bg),
            FilterState::Invalid(e) => {
                bg = bg.bg(theme.filter_err_bg);
                let err = Style::default()
                    .fg(ratatui::style::Color::Yellow)
                    .add_modifier(Modifier::UNDERLINED | Modifier::BOLD);
                let s = e.span.start.min(t.len());
                let end = e.span.end.clamp(s, t.len());
                if let (Some(a), Some(m), Some(b)) = (t.get(..s), t.get(s..end), t.get(end..)) {
                    spans.push(Span::raw(a));
                    spans.push(Span::styled(m, err));
                    spans.push(Span::raw(b));
                    if s == end {
                        // Boş aralık (ör. eksik değer): imleci işaretle.
                        cursor = Span::styled("█", err);
                    }
                } else {
                    spans.push(Span::raw(t));
                }
            }
        }
    }
    if spans.len() == 1 {
        spans.push(Span::raw(t));
    }
    spans.push(cursor);
    Paragraph::new(Line::from(spans)).style(bg)
}

/// Birden çok tamamlama adayı varsa giriş satırının üstünde açılır liste.
fn draw_completion(f: &mut Frame, app: &App, input: Rect) {
    const MAX: usize = 8;
    let Some(comp) = &app.completion else {
        return;
    };
    let sel = comp.index.unwrap_or(0);
    let skip = (sel + 1).saturating_sub(MAX);
    let shown = comp.candidates.len().min(MAX);
    let h = u16::try_from(shown + 2).unwrap_or(u16::MAX).min(input.y);
    let w = comp
        .candidates
        .iter()
        .map(|n| n.len())
        .max()
        .unwrap_or(0)
        .saturating_add(4);
    let w = u16::try_from(w).unwrap_or(u16::MAX).min(input.width);
    let popup = Rect::new(input.x, input.y - h, w, h);
    let lines: Vec<Line> = comp
        .candidates
        .iter()
        .enumerate()
        .skip(skip)
        .take(MAX)
        .map(|(i, n)| {
            let mut st = Style::default();
            if comp.index == Some(i) {
                st = st.bg(app.theme.selected_bg).add_modifier(Modifier::BOLD);
            }
            Line::styled(*n, st)
        })
        .collect();
    let title = format!(" {} aday ", comp.candidates.len());
    f.render_widget(Clear, popup);
    f.render_widget(
        Paragraph::new(lines).block(block(&title, true, &app.theme)),
        popup,
    );
}

fn draw_list(f: &mut Frame, app: &mut App, area: Rect) {
    let visible = usize::from(area.height.saturating_sub(3));
    if let Some(sel) = app.selected {
        keep_visible(&mut app.list_offset, sel, visible);
    }
    let max_off = app.displayed_len().saturating_sub(visible);
    app.list_offset = app.list_offset.min(max_off);
    let theme = &app.theme;
    let end = (app.list_offset + visible).min(app.displayed_len());
    let rows = (app.list_offset..end).filter_map(|i| {
        let e = app.store.get(app.store_index(i)?)?;
        let s = &e.summary;
        let mut style = Style::default().fg(theme.protocol_color(s.protocol, e.malformed));
        if Some(i) == app.selected {
            style = style.bg(theme.selected_bg).add_modifier(Modifier::BOLD);
        }
        Some(
            Row::new(vec![
                Cell::from(e.number.to_string()),
                Cell::from(format!("{:.6}", app.store.rel_time(&e))),
                Cell::from(s.src.clone()),
                Cell::from(s.dst.clone()),
                Cell::from(s.protocol),
                Cell::from(s.len.to_string()),
                Cell::from(s.info.clone()),
            ])
            .style(style),
        )
    });
    let header = Row::new([
        "No", "Zaman", "Kaynak", "Hedef", "Protokol", "Uzunluk", "Bilgi",
    ])
    .style(Style::default().add_modifier(Modifier::BOLD | Modifier::UNDERLINED));
    let widths = [
        Constraint::Length(7),
        Constraint::Length(11),
        Constraint::Length(22),
        Constraint::Length(22),
        Constraint::Length(8),
        Constraint::Length(7),
        Constraint::Fill(1),
    ];
    let table = Table::new(rows, widths).header(header).block(block(
        " Paketler ",
        app.focus == Panel::List,
        theme,
    ));
    f.render_widget(table, area);
}

fn draw_tree(f: &mut Frame, app: &mut App, area: Rect) {
    let visible = usize::from(area.height.saturating_sub(2));
    let focused = app.focus == Panel::Tree;
    let sel = app.tree_selected;
    let mut offset = app.tree_offset;
    keep_visible(&mut offset, sel, visible);
    let theme = app.theme.clone();
    let lines: Vec<Line> = match app.tree() {
        Some((_, rows)) => rows
            .iter()
            .enumerate()
            .skip(offset)
            .take(visible)
            .map(|(i, r)| {
                let marker = match (r.has_children, r.expanded) {
                    (false, _) => "  ",
                    (true, false) => "▸ ",
                    (true, true) => "▾ ",
                };
                let mut style = Style::default();
                if r.malformed {
                    style = style.fg(theme.malformed);
                }
                if i == sel {
                    style = style.bg(theme.selected_bg).add_modifier(Modifier::BOLD);
                }
                Line::styled(
                    format!("{}{marker}{}", "  ".repeat(r.depth), r.label),
                    style,
                )
            })
            .collect(),
        None => vec![Line::from("(paket seçilmedi)")],
    };
    app.tree_offset = offset;
    f.render_widget(
        Paragraph::new(lines).block(block(" Katmanlar ", focused, &theme)),
        area,
    );
}

/// Tek hex satırı: ofset, 16 bayt hex, ASCII; `hl` aralığındaki baytlar vurgulu.
#[must_use]
pub fn hex_line(
    data: &[u8],
    line: usize,
    hl: Option<&Range<usize>>,
    theme: &Theme,
) -> Line<'static> {
    let start = line * 16;
    let end = (start + 16).min(data.len());
    let hl_style = Style::default()
        .bg(theme.hex_highlight_bg)
        .add_modifier(Modifier::BOLD);
    let is_hl = |i: usize| hl.is_some_and(|r| r.contains(&i));
    let mut spans = vec![Span::styled(
        format!("{start:04x}  "),
        Style::default().fg(theme.border),
    )];
    for i in start..start + 16 {
        let text = data
            .get(i)
            .map_or_else(|| "  ".to_string(), |b| format!("{b:02x}"));
        let style = if i < end && is_hl(i) {
            hl_style
        } else {
            Style::default()
        };
        spans.push(Span::styled(text, style));
        spans.push(Span::raw(if i - start == 7 { "  " } else { " " }));
    }
    spans.push(Span::raw(" "));
    for (i, &b) in data.iter().enumerate().take(end).skip(start) {
        let c = if b.is_ascii_graphic() || b == b' ' {
            char::from(b)
        } else {
            '.'
        };
        let style = if is_hl(i) { hl_style } else { Style::default() };
        spans.push(Span::styled(c.to_string(), style));
    }
    Line::from(spans)
}

fn draw_hex(f: &mut Frame, app: &mut App, area: Rect) {
    let visible = usize::from(area.height.saturating_sub(2));
    let row = app.selected_row();
    let focused = app.focus == Panel::Hex;
    let theme = app.theme.clone();
    let Some(e) = app.selected_index().and_then(|i| app.store.get(i)) else {
        f.render_widget(
            Paragraph::new("").block(block(" Hex ", focused, &theme)),
            area,
        );
        return;
    };
    let data = &e.raw.data;
    let hl = row.and_then(|r| highlight_range(r.offset, r.len, data.len()));
    let hl_start = hl.as_ref().map(|r| r.start);
    let mut offset = app.hex_offset;
    if hl_start != app.last_hl {
        if let Some(s) = hl_start {
            keep_visible(&mut offset, s / 16, visible);
        }
    }
    let total = data.len().div_ceil(16);
    offset = offset.min(total.saturating_sub(1));
    let lines: Vec<Line> = (offset..total.min(offset + visible))
        .map(|l| hex_line(data, l, hl.as_ref(), &theme))
        .collect();
    app.hex_offset = offset;
    app.last_hl = hl_start;
    f.render_widget(
        Paragraph::new(lines).block(block(" Hex ", focused, &theme)),
        area,
    );
}

fn draw_status(f: &mut Frame, app: &App, area: Rect) {
    let mut parts = vec![
        Span::styled(
            format!(" {} ", app.source_name()),
            Style::default().add_modifier(Modifier::BOLD),
        ),
        Span::raw(format!(
            "│ gösterilen/toplam: {}/{} │ düşen: {} ",
            app.displayed_len(),
            app.store.total() + app.pending_len() as u64,
            app.dropped()
        )),
    ];
    if let Some(InputLine {
        kind: InputKind::Filter,
        state: FilterState::Invalid(e),
        ..
    }) = &app.input
    {
        parts.push(Span::styled(
            format!("│ hata: {} ", e.msg),
            Style::default()
                .fg(app.theme.malformed)
                .add_modifier(Modifier::BOLD),
        ));
    }
    if let Some(pct) = app.filter_progress() {
        parts.push(Span::styled(
            format!("│ filtreleniyor %{pct} "),
            Style::default().fg(app.theme.arp),
        ));
    }
    if app.paused {
        parts.push(Span::styled(
            format!("│ PAUSED (+{}) ", app.pending_len()),
            Style::default()
                .fg(app.theme.arp)
                .add_modifier(Modifier::BOLD),
        ));
    }
    if app.autoscroll {
        parts.push(Span::styled(
            "│ AUTOSCROLL ",
            Style::default()
                .fg(app.theme.http)
                .add_modifier(Modifier::BOLD),
        ));
    }
    if let Some(pct) = app.store.index_progress() {
        parts.push(Span::styled(
            format!("│ indeksleniyor %{pct} "),
            Style::default().fg(app.theme.arp),
        ));
    }
    if let Some(err) = app.store.error() {
        parts.push(Span::styled(
            format!("│ hata: {err} "),
            Style::default().fg(app.theme.malformed),
        ));
    }
    if let Some(msg) = &app.message {
        parts.push(Span::raw(format!("│ {msg} ")));
    }
    if !app.filter_text.is_empty() {
        parts.push(Span::raw(format!("│ filtre: {} ", app.filter_text)));
    }
    parts.push(Span::raw("│ ?: yardım"));
    f.render_widget(
        Paragraph::new(Line::from(parts)).style(Style::default().bg(app.theme.status_bg)),
        area,
    );
}

fn draw_help(f: &mut Frame, theme: &Theme) {
    let area = f.area();
    let h = u16::try_from(HELP.len() + 2)
        .unwrap_or(u16::MAX)
        .min(area.height);
    let w = 50.min(area.width);
    let r = Rect::new(
        area.x + (area.width - w) / 2,
        area.y + (area.height - h) / 2,
        w,
        h,
    );
    let lines: Vec<Line> = HELP
        .iter()
        .map(|(k, v)| {
            Line::from(vec![
                Span::styled(format!("{k:<18}"), Style::default().fg(theme.border_focus)),
                Span::raw(*v),
            ])
        })
        .collect();
    f.render_widget(Clear, r);
    f.render_widget(
        Paragraph::new(lines).block(block(" Yardım ", true, theme)),
        r,
    );
}
