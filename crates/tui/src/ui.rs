//! Çizim: paneller (liste, katman ağacı, hex) ve ekran iskeleti. Üst çubuk,
//! durum çubuğu, bildirim, palet ve yardım [`crate::chrome`] içindedir.

use std::ops::Range;

use ratatui::layout::{Alignment, Constraint, Layout, Margin, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{
    Block, BorderType, Borders, Cell, Paragraph, Row, Scrollbar, ScrollbarOrientation,
    ScrollbarState, Table,
};
use ratatui::Frame;

use crate::app::{App, Panel};
use crate::chrome;
use crate::icons::IconSet;
use crate::theme::{ColorRule, Theme};
use crate::tree::{guide_prefixes, highlight_range};
use crate::views::{draw_conversations, draw_follow, draw_stats, View};

/// Yuvarlak köşeli panel bloğu: odaklıysa vurgu renginde ve kalın, değilse soluk.
pub(crate) fn panel_block<'a>(title: impl Into<String>, focused: bool, theme: &Theme) -> Block<'a> {
    let (color, mods) = if focused {
        (theme.border_focus, Modifier::BOLD)
    } else {
        (theme.border, Modifier::empty())
    };
    let title_color = if focused { theme.accent } else { theme.dim };
    Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(color).add_modifier(mods))
        .title(Line::styled(
            title.into(),
            Style::default().fg(title_color).add_modifier(mods),
        ))
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

/// Panelin sağ kenarına kaydırma çubuğu (içerik sığmıyorsa).
fn scrollbar(
    f: &mut Frame,
    area: Rect,
    total: usize,
    visible: usize,
    offset: usize,
    icons: IconSet,
    theme: &Theme,
) {
    if visible == 0 || total <= visible {
        return;
    }
    let (track, thumb) = icons.scroll();
    let mut state = ScrollbarState::new(total - visible)
        .position(offset.min(total - visible))
        .viewport_content_length(visible);
    f.render_stateful_widget(
        Scrollbar::new(ScrollbarOrientation::VerticalRight)
            .begin_symbol(None)
            .end_symbol(None)
            .track_symbol(Some(track))
            .thumb_symbol(thumb)
            .track_style(Style::default().fg(theme.border))
            .thumb_style(Style::default().fg(theme.accent)),
        area.inner(Margin {
            vertical: 1,
            horizontal: 0,
        }),
        &mut state,
    );
}

/// Spinner için ~8 Hz'lik tik.
fn tick(app: &App) -> u64 {
    u64::try_from(app.started.elapsed().as_millis() / 120).unwrap_or(0)
}

/// Tüm ekranı çizer.
pub fn draw(f: &mut Frame, app: &mut App) {
    let input_h = u16::from(app.input.is_some());
    let [header, tabs, body, input, status] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Min(4),
        Constraint::Length(input_h),
        Constraint::Length(1),
    ])
    .areas(f.area());
    f.render_widget(
        Block::default().style(Style::default().fg(app.theme.fg).bg(app.theme.bg)),
        f.area(),
    );
    chrome::draw_header(f, app, header);
    chrome::draw_tabs(f, app, tabs);
    match app.view {
        View::Packets => draw_packets(f, app, body),
        View::Follow => draw_follow(f, app, body),
        View::Conversations => draw_conversations(f, app, body),
        View::Stats => draw_stats(f, app, body),
    }
    if let Some(inp) = &app.input {
        f.render_widget(chrome::input_line(inp, &app.theme), input);
    }
    chrome::draw_status(f, app, status);
    if app.completion.is_none() {
        chrome::draw_filter_error(f, app, input);
    }
    chrome::draw_palette(f, app, input);
    chrome::draw_completion(f, app, input);
    chrome::draw_toast(f, app, body);
    if app.show_help {
        chrome::draw_help(f, app);
    }
}

/// Paket görünümü: düzene (dikey/yatay/zoom) göre üç panel.
fn draw_packets(f: &mut Frame, app: &mut App, body: Rect) {
    let l = app.layout;
    let none = Rect::default();
    let (list, tree, hex) = if l.zoom {
        match app.focus {
            Panel::List => (body, none, none),
            Panel::Tree => (none, body, none),
            Panel::Hex => (none, none, body),
        }
    } else if l.horizontal {
        let [top, bottom] = Layout::vertical([
            Constraint::Percentage(l.split),
            Constraint::Percentage(100 - l.split),
        ])
        .areas(body);
        // Hex satırı 72 sütun sürer; dar terminalde alanın yarısından azına düşmez.
        let hex_w = 74.min(bottom.width * 2 / 3).max(bottom.width / 2);
        let [tree, hex] =
            Layout::horizontal([Constraint::Fill(1), Constraint::Length(hex_w)]).areas(bottom);
        (top, tree, hex)
    } else {
        let rest = (100 - l.split) * 55 / 100;
        let [list, tree, hex] = Layout::vertical([
            Constraint::Percentage(l.split),
            Constraint::Percentage(rest),
            Constraint::Min(4),
        ])
        .areas(body);
        (list, tree, hex)
    };
    app.areas.list = list;
    app.areas.tree = tree;
    app.areas.hex = hex;
    if list.area() > 0 {
        draw_list(f, app, list);
    }
    if tree.area() > 0 {
        draw_tree(f, app, tree);
    }
    if hex.area() > 0 {
        draw_hex(f, app, hex);
    }
}

/// Boş liste: ortalanmış mesaj (+ canlıysa spinner).
fn draw_empty(f: &mut Frame, app: &App, area: Rect) {
    let inner = area.inner(Margin::new(1, 1));
    if inner.height == 0 {
        return;
    }
    let (text, spin) = if !app.filter_text.is_empty() && app.store.total() > 0 {
        if app.filter_progress().is_some() {
            ("Filtreleniyor".to_owned(), true)
        } else {
            ("Filtreyle eşleşen paket yok".to_owned(), false)
        }
    } else {
        (
            format!("Paket bekleniyor{}", app.icons.ellipsis()),
            app.is_live(),
        )
    };
    let line = if spin {
        Line::from(vec![
            Span::styled(
                format!("{} ", app.icons.spinner(tick(app))),
                Style::default().fg(app.theme.accent),
            ),
            Span::styled(text, Style::default().fg(app.theme.dim)),
        ])
    } else {
        Line::styled(text, Style::default().fg(app.theme.dim))
    };
    let y = inner.y + inner.height / 2;
    f.render_widget(
        Paragraph::new(line).alignment(Alignment::Center),
        Rect::new(inner.x, y, inner.width, 1),
    );
}

#[allow(clippy::too_many_lines)]
fn draw_list(f: &mut Frame, app: &mut App, area: Rect) {
    let visible = usize::from(area.height.saturating_sub(3));
    if let Some(sel) = app.selected {
        keep_visible(&mut app.list_offset, sel, visible);
    }
    let max_off = app.displayed_len().saturating_sub(visible);
    app.list_offset = app.list_offset.min(max_off);
    let focused = app.focus == Panel::List;
    let title = format!(
        " {}Paketler {}/{} ",
        app.icons.title_packets(),
        app.displayed_len(),
        app.store.len()
    );
    if app.displayed_len() == 0 {
        f.render_widget(panel_block(title, focused, &app.theme), area);
        draw_empty(f, app, area);
        return;
    }
    let theme = &app.theme;
    let icons = app.icons;
    let end = (app.list_offset + visible).min(app.displayed_len());
    let resolve = app.resolve_names;
    let an = &app.analyzer;
    let rows = (app.list_offset..end).filter_map(|i| {
        let e = app.store.get(app.store_index(i)?)?;
        let s = &e.summary;
        let flags = e.flow.map(|t| t.flags).unwrap_or_default();
        let selected = Some(i) == app.selected;
        let mut style = if e.malformed {
            Style::default().fg(theme.malformed)
        } else {
            // Renklendirme kuralları: görünür satırlar yeniden ayrıştırılır, ilk eşleşen.
            let d = an.dissect(&e.raw, e.number, e.flow.as_ref());
            app.coloring
                .iter()
                .find(|r| r.matches(&d, &e.raw))
                .map_or_else(|| Style::default().fg(theme.other), ColorRule::style)
        };
        let mut dim = Style::default().fg(theme.dim);
        if selected {
            // Seçimde yüksek kontrast: protokol rengi yalnızca sol çubukta/rozette kalır.
            style = Style::default()
                .fg(theme.selected_fg)
                .bg(theme.selected_bg)
                .add_modifier(Modifier::BOLD);
            dim = Style::default().fg(theme.selected_fg);
        } else if style.bg.is_none() && i % 2 == 1 {
            style = style.bg(theme.zebra_bg);
        }
        let proto = theme.badge_color(s.protocol, e.malformed);
        let badge = Style::default()
            .fg(theme.badge_fg)
            .bg(proto)
            .add_modifier(Modifier::BOLD);
        let flag_color = if flags.has_warning() {
            theme.warn
        } else {
            theme.danger
        };
        let (src, dst) = if resolve {
            (an.resolve(&s.src).to_owned(), an.resolve(&s.dst).to_owned())
        } else {
            (s.src.clone(), s.dst.clone())
        };
        Some(
            Row::new(vec![
                Cell::from(icons.bar()).style(Style::default().fg(proto)),
                Cell::from(icons.flag(flags)).style(Style::default().fg(flag_color)),
                Cell::from(Line::from(e.number.to_string()).right_aligned()).style(dim),
                Cell::from(format!("{:.6}", app.store.rel_time(&e))).style(dim),
                Cell::from(src),
                Cell::from(dst),
                Cell::from(Span::styled(format!(" {:<6} ", s.protocol), badge)),
                Cell::from(Line::from(s.len.to_string()).right_aligned()),
                Cell::from(e.process.clone().unwrap_or_default()).style(dim),
                Cell::from(format!("{}{}", flags.info_prefix(), s.info)),
            ])
            .style(style),
        )
    });
    let header = Row::new([
        Cell::from(""),
        Cell::from(""),
        Cell::from(Line::from("No").right_aligned()),
        Cell::from("Zaman"),
        Cell::from("Kaynak"),
        Cell::from("Hedef"),
        Cell::from("Protokol"),
        Cell::from(Line::from("Uzunluk").right_aligned()),
        Cell::from("Süreç"),
        Cell::from("Bilgi"),
    ])
    .style(
        Style::default()
            .fg(theme.accent)
            .add_modifier(Modifier::BOLD),
    );
    let widths = [
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Length(7),
        Constraint::Length(11),
        Constraint::Length(18),
        Constraint::Length(18),
        Constraint::Length(8),
        Constraint::Length(7),
        Constraint::Length(10),
        Constraint::Fill(1),
    ];
    let table = Table::new(rows, widths)
        .header(header)
        .block(panel_block(title, focused, theme));
    f.render_widget(table, area);
    scrollbar(
        f,
        area,
        app.displayed_len(),
        visible,
        app.list_offset,
        icons,
        &app.theme,
    );
}

fn draw_tree(f: &mut Frame, app: &mut App, area: Rect) {
    let visible = usize::from(area.height.saturating_sub(2));
    let focused = app.focus == Panel::Tree;
    let sel = app.tree_selected;
    let mut offset = app.tree_offset;
    keep_visible(&mut offset, sel, visible);
    let theme = app.theme.clone();
    let icons = app.icons;
    let guides = icons.guides();
    let mut total = 0;
    let (title, lines): (String, Vec<Line>) = match app.tree() {
        Some((d, rows)) => {
            total = rows.len();
            let prefixes = guide_prefixes(rows, guides);
            let range = rows
                .get(sel)
                .filter(|r| r.len > 0)
                .map(|r| format!(" · bayt {}..{}", r.offset, r.offset + r.len))
                .unwrap_or_default();
            let title = format!(
                " {}Katmanlar {}/{}{range} ",
                icons.title_tree(),
                sel.min(total.saturating_sub(1)) + 1,
                total
            );
            let lines = rows
                .iter()
                .zip(&prefixes)
                .enumerate()
                .skip(offset)
                .take(visible)
                .map(|(i, (r, prefix))| {
                    let marker = match (r.has_children, r.expanded) {
                        (false, _) => "  ",
                        (true, false) => icons.closed(),
                        (true, true) => icons.open(),
                    };
                    let marker = if r.has_children {
                        format!("{marker} ")
                    } else {
                        marker.to_owned()
                    };
                    let mut label_style = Style::default();
                    let mut label = r.label.clone();
                    if r.depth == 0 {
                        let proto = r
                            .path
                            .first()
                            .and_then(|&li| d.layers.get(li))
                            .map_or("", |l| l.protocol);
                        label_style = label_style
                            .fg(theme.layer_color(proto))
                            .add_modifier(Modifier::BOLD);
                    }
                    if r.malformed {
                        label = format!("{} {label}", icons.warn());
                        label_style = label_style.fg(theme.danger).add_modifier(Modifier::BOLD);
                    }
                    if i == sel && r.depth > 0 && !r.malformed {
                        label_style = label_style
                            .fg(theme.selected_fg)
                            .add_modifier(Modifier::BOLD);
                    }
                    Line::from(vec![
                        Span::styled(prefix.clone(), Style::default().fg(theme.border_focus)),
                        Span::styled(marker, Style::default().fg(theme.accent)),
                        Span::styled(label, label_style),
                    ])
                })
                .collect();
            (title, lines)
        }
        None => (
            format!(" {}Katmanlar ", icons.title_tree()),
            vec![Line::styled(
                "(paket seçilmedi)",
                Style::default().fg(theme.dim),
            )],
        ),
    };
    app.tree_offset = offset;
    f.render_widget(
        Paragraph::new(lines).block(panel_block(title, focused, &theme)),
        area,
    );
    // Seçili satırın zemini tüm genişliğe yayılır.
    if sel >= offset && sel < offset + visible && sel < total {
        let y = area.y + 1 + u16::try_from(sel - offset).unwrap_or(0);
        f.buffer_mut().set_style(
            Rect::new(area.x + 1, y, area.width.saturating_sub(2), 1),
            Style::default().bg(theme.selected_bg),
        );
    }
    scrollbar(f, area, total, visible, offset, icons, &theme);
}

/// Bayt sınıfına göre stil: 0x00 soluk, yazdırılabilir normal, kontrol / üst bayt ayrı ton.
fn byte_style(b: u8, theme: &Theme) -> Style {
    match b {
        0 => Style::default().fg(theme.dim),
        0x20..=0x7e => Style::default(),
        0x80..=0xff => Style::default().fg(theme.hex_high),
        _ => Style::default().fg(theme.hex_ctrl),
    }
}

/// Tek hex satırı: ofset, 16 bayt hex, ASCII; `hl` aralığındaki baytlar vurgulu
/// (hex ve ASCII'de aynı renkte).
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
        .fg(theme.hex_highlight_fg)
        .bg(theme.hex_highlight_bg)
        .add_modifier(Modifier::BOLD);
    let is_hl = |i: usize| hl.is_some_and(|r| r.contains(&i));
    let mut spans = vec![Span::styled(
        format!("{start:04x}  "),
        Style::default().fg(theme.dim),
    )];
    for i in start..start + 16 {
        let (text, style) = match data.get(i) {
            Some(&b) if i < end => (
                format!("{b:02x}"),
                if is_hl(i) {
                    hl_style
                } else {
                    byte_style(b, theme)
                },
            ),
            _ => ("  ".to_string(), Style::default()),
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
        let style = if is_hl(i) {
            hl_style
        } else if b.is_ascii_graphic() || b == b' ' {
            Style::default()
        } else {
            byte_style(b, theme)
        };
        spans.push(Span::styled(c.to_string(), style));
    }
    Line::from(spans)
}

fn draw_hex(f: &mut Frame, app: &mut App, area: Rect) {
    let visible = usize::from(area.height.saturating_sub(2));
    let row = app.selected_row();
    let focused = app.focus == crate::app::Panel::Hex;
    let theme = app.theme.clone();
    let icons = app.icons;
    let Some(e) = app.selected_index().and_then(|i| app.store.get(i)) else {
        f.render_widget(
            Paragraph::new("").block(panel_block(
                format!(" {}Hex ", icons.title_hex()),
                focused,
                &theme,
            )),
            area,
        );
        return;
    };
    let data = &e.raw.data;
    let hl = row
        .as_ref()
        .and_then(|r| highlight_range(r.offset, r.len, data.len()));
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
    let width = usize::from(area.width);
    let field = row
        .filter(|r| r.len > 0)
        .map(|r| {
            let mut name: String = r
                .label
                .chars()
                .take(width.saturating_sub(24).clamp(8, 48))
                .collect();
            if name.chars().count() < r.label.chars().count() {
                name.push_str(icons.ellipsis());
            }
            format!(" · {name}")
        })
        .unwrap_or_default();
    let title = format!(" {}Hex{field} · {} bayt ", icons.title_hex(), data.len());
    app.hex_offset = offset;
    app.last_hl = hl_start;
    f.render_widget(
        Paragraph::new(lines).block(panel_block(title, focused, &theme)),
        area,
    );
    scrollbar(f, area, total, visible, offset, icons, &theme);
}
