//! Ekran kromu: üst başlık çubuğu, sekmeler, giriş satırı, durum çubuğu,
//! bildirim (toast), komut paleti ve yardım penceresi.

#![allow(clippy::many_single_char_names)]

use std::time::Duration;

use ratatui::layout::{Alignment, Constraint, Layout, Margin, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::symbols;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Borders, Clear, Paragraph, Sparkline, Tabs, Wrap};
use ratatui::Frame;

use crate::app::{App, FilterState, InputKind, InputLine, ToastKind};
use crate::icons::IconSet;
use crate::keymap::{format_key, Action};
use crate::theme::Theme;
use crate::ui::panel_block;
use crate::views::{fmt_bytes, View};

const ASCII_BARS: symbols::bar::Set = symbols::bar::Set {
    full: "#",
    seven_eighths: "#",
    three_quarters: "=",
    five_eighths: "=",
    half: "=",
    three_eighths: "-",
    one_quarter: "-",
    one_eighth: ".",
    empty: " ",
};

/// `HH:MM:SS`.
fn fmt_clock(d: Duration) -> String {
    let s = d.as_secs();
    format!("{:02}:{:02}:{:02}", s / 3600, s / 60 % 60, s % 60)
}

// ------------------------------------------------------------------ başlık

/// Üst çubuk: logo, kaynak, durum rozeti, süre, pps/bps ve küçük sparkline.
pub(crate) fn draw_header(f: &mut Frame, app: &App, area: Rect) {
    let t = &app.theme;
    let icons = app.icons;
    f.render_widget(
        Block::default().style(Style::default().fg(t.fg).bg(t.header_bg)),
        area,
    );
    let blink = (app.started.elapsed().as_millis() / 500).is_multiple_of(2);
    let (badge_icon, badge_text, badge_style) = if app.paused {
        (
            icons.paused(),
            "DURAKLATILDI",
            Style::default().fg(t.warn).add_modifier(Modifier::BOLD),
        )
    } else if app.is_live() {
        let c = if blink || icons.is_ascii() {
            t.danger
        } else {
            t.dim
        };
        (
            icons.live(),
            "CANLI",
            Style::default().fg(c).add_modifier(Modifier::BOLD),
        )
    } else {
        (
            icons.file(),
            "DOSYA",
            Style::default().fg(t.accent).add_modifier(Modifier::BOLD),
        )
    };
    let st = &app.analyzer.stats;
    let elapsed = if app.is_live() {
        app.started.elapsed()
    } else {
        st.time_range()
            .and_then(|(a, b)| b.duration_since(a).ok())
            .unwrap_or_default()
    };
    let dim = Style::default().fg(t.dim);
    let left = Line::from(vec![
        Span::styled(
            format!(" {}pakiz", icons.logo()),
            Style::default().fg(t.accent).add_modifier(Modifier::BOLD),
        ),
        Span::styled(if icons.is_ascii() { "  |  " } else { "  │  " }, dim),
        Span::styled(
            source_label(app),
            Style::default().add_modifier(Modifier::BOLD),
        ),
        Span::raw("  "),
        Span::styled(format!("{badge_icon}{badge_text}"), badge_style),
        Span::styled(format!("  {}", fmt_clock(elapsed)), dim),
    ]);
    // Canlıda son tamamlanan saniye; dosyada ortalama.
    let (pps, bps, tag) = if app.is_live() {
        let (p, b) = (st.pps_series(), st.bps_series());
        let at = |v: &[u64]| {
            v.len()
                .checked_sub(2)
                .and_then(|i| v.get(i))
                .copied()
                .unwrap_or(0)
        };
        (at(&p), at(&b), "")
    } else {
        let (p, b) = st.average();
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        (p as u64, b as u64, " ort")
    };
    let rate = format!("{pps} pps  {}/s{tag} ", fmt_bytes(bps));
    let rate_w = u16::try_from(rate.chars().count()).unwrap_or(u16::MAX);
    let spark_w: u16 = if area.width >= 90 { 18 } else { 0 };
    let [l, r, s] = Layout::horizontal([
        Constraint::Fill(1),
        Constraint::Length(rate_w),
        Constraint::Length(spark_w),
    ])
    .areas(area);
    f.render_widget(Paragraph::new(left), l);
    f.render_widget(
        Paragraph::new(rate).style(dim).alignment(Alignment::Right),
        r,
    );
    if spark_w > 0 {
        let series = st.pps_series();
        let w = usize::from(spark_w.saturating_sub(1));
        let tail = &series[series.len().saturating_sub(w)..];
        f.render_widget(
            Sparkline::default()
                .bar_set(if icons.is_ascii() {
                    ASCII_BARS
                } else {
                    symbols::bar::NINE_LEVELS
                })
                .data(tail)
                .style(Style::default().fg(t.accent).bg(t.header_bg)),
            Rect::new(s.x, s.y, s.width.saturating_sub(1), s.height),
        );
    }
}

/// Kaynak adı: arayüz adı ya da dosyanın yalnızca adı (dizinsiz).
fn source_label(app: &App) -> String {
    let name = app.source_name();
    if app.is_live() {
        return name.to_owned();
    }
    std::path::Path::new(name)
        .file_name()
        .map_or_else(|| name.to_owned(), |n| n.to_string_lossy().into_owned())
}

fn view_label(v: View) -> (&'static str, Action) {
    match v {
        View::Packets => ("Paketler", Action::Back),
        View::Follow => ("Akış", Action::Follow),
        View::Conversations => ("Konuşmalar", Action::Conversations),
        View::Stats => ("İstatistik", Action::Statistics),
    }
}

/// Görünüm sekmeleri (aktif olan vurgulu, kısayol ipuçlu).
pub(crate) fn draw_tabs(f: &mut Frame, app: &App, area: Rect) {
    let t = &app.theme;
    let idx = View::ALL.iter().position(|&v| v == app.view).unwrap_or(0);
    let titles = View::ALL.iter().enumerate().map(|(i, &v)| {
        let (name, action) = view_label(v);
        let hint_fg = if i == idx { t.badge_fg } else { t.dim };
        Line::from(vec![
            Span::raw(name),
            Span::styled(
                format!(" {}", app.key_hint(action)),
                Style::default().fg(hint_fg).add_modifier(Modifier::DIM),
            ),
        ])
    });
    let layout_note = if app.view == View::Packets {
        format!(
            "düzen: {}{} {}% ",
            if app.layout.horizontal {
                "yatay"
            } else {
                "dikey"
            },
            if app.layout.zoom { " · zoom" } else { "" },
            app.layout.split
        )
    } else {
        String::new()
    };
    let note_w = u16::try_from(layout_note.chars().count()).unwrap_or(0);
    let [tabs, note] =
        Layout::horizontal([Constraint::Fill(1), Constraint::Length(note_w)]).areas(area);
    f.render_widget(
        Tabs::new(titles)
            .select(idx)
            .style(Style::default().fg(t.fg).bg(t.bg))
            .highlight_style(
                Style::default()
                    .fg(t.badge_fg)
                    .bg(t.accent)
                    .add_modifier(Modifier::BOLD),
            )
            .padding(" ", " ")
            .divider(Span::styled("│", Style::default().fg(t.border))),
        tabs,
    );
    f.render_widget(
        Paragraph::new(layout_note)
            .style(Style::default().fg(t.dim).bg(t.bg))
            .alignment(Alignment::Right),
        note,
    );
}

// ------------------------------------------------------------------ giriş

/// Giriş satırı. Filtrede arka plan geçerliyse yeşil, hatalıysa kırmızı (açık yazı);
/// hata aralığının altı çizilir.
pub(crate) fn input_line<'a>(inp: &'a InputLine, theme: &Theme) -> Paragraph<'a> {
    let prefix = match inp.kind {
        InputKind::Filter => "/",
        InputKind::Command => ":",
    };
    let t = inp.text.as_str();
    let mut spans = vec![Span::styled(
        prefix,
        Style::default()
            .fg(theme.accent)
            .add_modifier(Modifier::BOLD),
    )];
    let mut bg = Style::default();
    let mut cursor = Span::raw("█");
    if inp.kind == InputKind::Filter {
        match &inp.state {
            FilterState::Empty => {}
            FilterState::Valid => bg = bg.bg(theme.filter_ok_bg).fg(theme.filter_err_fg),
            FilterState::Invalid(e) => {
                bg = bg.bg(theme.filter_err_bg).fg(theme.filter_err_fg);
                let err = Style::default()
                    .fg(Color::Yellow)
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

/// Satır sayısı: `text`, `width` genişliğe kelime kaydırmayla.
fn wrapped_lines(text: &str, width: usize) -> usize {
    let width = width.max(1);
    let mut lines = 1;
    let mut col = 0;
    for word in text.split_whitespace() {
        let w = word.chars().count();
        if col == 0 {
            col = w;
        } else if col + 1 + w <= width {
            col += 1 + w;
        } else {
            lines += 1;
            col = w;
        }
        while col > width {
            lines += 1;
            col -= width;
        }
    }
    lines
}

/// Filtre hatası: giriş satırının üstünde ayrı, kaydırmalı kutu (kesilmez).
pub(crate) fn draw_filter_error(f: &mut Frame, app: &App, input: Rect) {
    let Some(InputLine {
        kind: InputKind::Filter,
        state: FilterState::Invalid(e),
        ..
    }) = &app.input
    else {
        return;
    };
    let t = &app.theme;
    let text = format!("hata: {} (sütun {})", e.msg, e.span.start + 1);
    let w = input.width.min(76);
    if w < 12 || input.y < 3 {
        return;
    }
    let inner_w = usize::from(w - 4);
    let lines = wrapped_lines(&text, inner_w).min(5);
    let h = (u16::try_from(lines).unwrap_or(5) + 2).min(input.y);
    let r = Rect::new(input.x, input.y - h, w, h);
    f.render_widget(Clear, r);
    f.render_widget(
        Paragraph::new(text)
            .wrap(Wrap { trim: true })
            .style(Style::default().fg(t.filter_err_fg).bg(t.filter_err_bg))
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_type(BorderType::Rounded)
                    .border_style(Style::default().fg(t.danger).bg(t.filter_err_bg))
                    .padding(ratatui::widgets::Padding::horizontal(1)),
            ),
        r,
    );
}

/// Komut paleti: `:` satırının üstünde filtrelenen aday listesi.
pub(crate) fn draw_palette(f: &mut Frame, app: &App, input: Rect) {
    const MAX: usize = 9;
    let cands = app.palette();
    if cands.is_empty() {
        return;
    }
    let t = &app.theme;
    let sel = app.palette_sel.min(cands.len() - 1);
    let skip = (sel + 1).saturating_sub(MAX);
    let shown = cands.len().min(MAX);
    let h = (u16::try_from(shown + 2).unwrap_or(u16::MAX)).min(input.y);
    let label_w = cands
        .iter()
        .map(|c| c.label.chars().count())
        .max()
        .unwrap_or(0);
    let desc_w = cands
        .iter()
        .map(|c| c.desc.chars().count())
        .max()
        .unwrap_or(0);
    let w = u16::try_from(label_w + desc_w + 8)
        .unwrap_or(u16::MAX)
        .min(input.width);
    if h < 3 || w < 10 {
        return;
    }
    let r = Rect::new(input.x, input.y - h, w, h);
    let lines: Vec<Line> = cands
        .iter()
        .enumerate()
        .skip(skip)
        .take(MAX)
        .map(|(i, c)| {
            let on = i == sel;
            let (name, desc, row) = if on {
                (
                    Style::default()
                        .fg(t.selected_fg)
                        .add_modifier(Modifier::BOLD),
                    Style::default().fg(t.selected_fg),
                    Style::default().bg(t.selected_bg),
                )
            } else {
                (
                    Style::default().fg(t.accent),
                    Style::default().fg(t.dim),
                    Style::default(),
                )
            };
            Line::from(vec![
                Span::styled(
                    if on { "▸ " } else { "  " }.replace('▸', app.icons.closed()),
                    name,
                ),
                Span::styled(format!("{:<label_w$}", c.label), name),
                Span::styled(format!("  {}", c.desc), desc),
            ])
            .style(row)
        })
        .collect();
    f.render_widget(Clear, r);
    f.render_widget(
        Paragraph::new(lines)
            .style(Style::default().fg(t.fg).bg(t.toast_bg))
            .block(
                panel_block(format!(" Komutlar {} · Tab/↑↓ ", cands.len()), true, t)
                    .style(Style::default().bg(t.toast_bg)),
            ),
        r,
    );
    fill_row(f, r, sel - skip, t.selected_bg);
}

/// Açılır listenin `row`. satırının zeminini tüm genişliğe yayar.
fn fill_row(f: &mut Frame, popup: Rect, row: usize, bg: Color) {
    let y = popup.y + 1 + u16::try_from(row).unwrap_or(0);
    if y + 1 < popup.bottom() {
        f.buffer_mut().set_style(
            Rect::new(popup.x + 1, y, popup.width.saturating_sub(2), 1),
            Style::default().bg(bg),
        );
    }
}

/// Birden çok tamamlama adayı varsa giriş satırının üstünde açılır liste.
pub(crate) fn draw_completion(f: &mut Frame, app: &App, input: Rect) {
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
                st = st
                    .fg(app.theme.selected_fg)
                    .bg(app.theme.selected_bg)
                    .add_modifier(Modifier::BOLD);
            }
            Line::styled(*n, st)
        })
        .collect();
    let title = format!(" {} aday ", comp.candidates.len());
    f.render_widget(Clear, popup);
    f.render_widget(
        Paragraph::new(lines)
            .style(Style::default().fg(app.theme.fg).bg(app.theme.toast_bg))
            .block(panel_block(title, true, &app.theme)),
        popup,
    );
    if comp.index.is_some() {
        fill_row(f, popup, sel - skip, app.theme.selected_bg);
    }
}

// ------------------------------------------------------------------ durum çubuğu

struct Segment {
    text: String,
    fg: Color,
    bg: Color,
    bold: bool,
}

impl Segment {
    fn new(text: impl Into<String>, fg: Color, bg: Color) -> Self {
        Self {
            text: text.into(),
            fg,
            bg,
            bold: false,
        }
    }

    fn bold(mut self) -> Self {
        self.bold = true;
        self
    }
}

/// Bölümleri ayırıcılarla (kutu: `▌`, nerd: powerline oku, ascii: `|`) soldan dizer.
fn powerline(segs: &[Segment], base: Color, theme: &Theme, icons: IconSet) -> Vec<Span<'static>> {
    let mut out = Vec::new();
    for (i, s) in segs.iter().enumerate() {
        let mut st = Style::default().fg(s.fg).bg(s.bg);
        if s.bold {
            st = st.add_modifier(Modifier::BOLD);
        }
        out.push(Span::styled(format!(" {} ", s.text), st));
        let next = segs.get(i + 1).map_or(base, |n| n.bg);
        let sep = if icons.is_ascii() {
            Style::default().fg(theme.dim).bg(next)
        } else {
            Style::default().fg(s.bg).bg(next)
        };
        out.push(Span::styled(icons.separator(), sep));
    }
    out
}

pub(crate) fn draw_status(f: &mut Frame, app: &App, area: Rect) {
    let t = &app.theme;
    let (mode, mode_bg) = match app.input.as_ref().map(|i| i.kind) {
        Some(InputKind::Filter) => ("FİLTRE", t.ok),
        Some(InputKind::Command) => ("KOMUT", t.warn),
        None => ("NORMAL", t.accent),
    };
    let mut segs = vec![
        Segment::new(mode, t.badge_fg, mode_bg).bold(),
        Segment::new(
            format!(
                "gösterilen/toplam: {}/{}",
                app.displayed_len(),
                app.store.total() + app.pending_len() as u64
            ),
            t.fg,
            t.seg_bg,
        ),
    ];
    let dropped = app.dropped();
    segs.push(if dropped > 0 {
        Segment::new(format!("düşen: {dropped}"), t.badge_fg, t.warn).bold()
    } else {
        Segment::new("düşen: 0", t.dim, t.status_bg)
    });
    if !app.filter_text.is_empty() {
        segs.push(Segment::new(
            format!("filtre: {}", app.filter_text),
            t.fg,
            t.seg_bg,
        ));
    }
    if let Some(pct) = app.filter_progress() {
        segs.push(Segment::new(
            format!("filtreleniyor %{pct}"),
            t.warn,
            t.status_bg,
        ));
    }
    if let Some(pct) = app.store.index_progress() {
        segs.push(Segment::new(
            format!("indeksleniyor %{pct}"),
            t.warn,
            t.status_bg,
        ));
    }
    if let Some(err) = app.store.error() {
        segs.push(Segment::new(format!("hata: {err}"), t.badge_fg, t.danger).bold());
    }
    if app.paused {
        segs.push(
            Segment::new(
                format!("PAUSED (+{})", app.pending_len()),
                t.badge_fg,
                t.warn,
            )
            .bold(),
        );
    }
    if app.resolve_names {
        segs.push(Segment::new("ad çözümleme", t.fg, t.seg_bg));
    }
    if app.autoscroll {
        segs.push(Segment::new("AUTOSCROLL", t.badge_fg, t.ok).bold());
    }
    let left = Line::from(powerline(&segs, t.status_bg, t, app.icons));
    let right = format!("{}: yardım ", app.key_hint(Action::Help));
    let rw = u16::try_from(right.chars().count()).unwrap_or(u16::MAX);
    f.render_widget(
        Block::default().style(Style::default().fg(t.fg).bg(t.status_bg)),
        area,
    );
    let [l, r] = Layout::horizontal([Constraint::Fill(1), Constraint::Length(rw)]).areas(area);
    f.render_widget(Paragraph::new(left), l);
    f.render_widget(
        Paragraph::new(right)
            .style(Style::default().fg(t.dim))
            .alignment(Alignment::Right),
        r,
    );
}

// ------------------------------------------------------------------ toast

/// Sağ üstte kısa süre görünen bildirim kutusu.
pub(crate) fn draw_toast(f: &mut Frame, app: &App, body: Rect) {
    let Some(toast) = &app.toast else {
        return;
    };
    let t = &app.theme;
    let ascii = app.icons.is_ascii();
    let (icon, color) = match toast.kind {
        ToastKind::Info => (if ascii { "i" } else { "ℹ" }, t.accent),
        ToastKind::Ok => (if ascii { "+" } else { "✔" }, t.ok),
        ToastKind::Warn => (if ascii { "!" } else { "⚠" }, t.warn),
        ToastKind::Error => (if ascii { "x" } else { "✖" }, t.danger),
    };
    let text = format!("{icon} {}", toast.text);
    let max_w = body.width.saturating_sub(2).min(64);
    if max_w < 12 || body.height < 3 {
        return;
    }
    let want = u16::try_from(text.chars().count() + 4).unwrap_or(u16::MAX);
    let w = want.clamp(14, max_w);
    let lines = wrapped_lines(&text, usize::from(w - 4)).min(4);
    let h = (u16::try_from(lines).unwrap_or(4) + 2).min(body.height);
    let r = Rect::new(body.right().saturating_sub(w + 1), body.y, w, h);
    f.render_widget(Clear, r);
    f.render_widget(
        Paragraph::new(text)
            .wrap(Wrap { trim: true })
            .style(Style::default().fg(t.toast_fg).bg(t.toast_bg))
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_type(BorderType::Rounded)
                    .border_style(Style::default().fg(color).add_modifier(Modifier::BOLD))
                    .padding(ratatui::widgets::Padding::horizontal(1)),
            ),
        r,
    );
}

// ------------------------------------------------------------------ yardım

struct Group {
    title: &'static str,
    entries: &'static [(&'static [Action], &'static str)],
}

use Action as A;

const GROUPS: &[Group] = &[
    Group {
        title: "Gezinme",
        entries: &[
            (&[A::Down], "aşağı"),
            (&[A::Up], "yukarı"),
            (&[A::Top], "başa"),
            (&[A::Bottom], "sona"),
            (&[A::HalfPageDown], "yarım sayfa aşağı"),
            (&[A::HalfPageUp], "yarım sayfa yukarı"),
        ],
    },
    Group {
        title: "Paneller",
        entries: &[
            (&[A::NextPanel], "sonraki panel (İstatistik: sekme)"),
            (&[A::Toggle], "ağaçta aç/kapa"),
            (&[A::Collapse], "dalı kapa"),
            (&[A::Expand], "dalı aç"),
            (&[A::Zoom], "odaklı paneli büyüt / geri al"),
            (&[A::ToggleLayout], "dikey ↔ yatay düzen"),
            (&[A::Grow], "odaklı paneli büyüt"),
            (&[A::Shrink], "odaklı paneli küçült"),
        ],
    },
    Group {
        title: "Görünümler",
        entries: &[
            (&[A::Follow], "seçili akışı izle (Follow Stream)"),
            (&[A::Conversations], "konuşmalar tablosu"),
            (&[A::Statistics], "istatistikler"),
            (&[A::Back], "paket listesine dön"),
            (&[A::CycleMode], "Follow: ASCII / Hex / Raw"),
            (&[A::Sort], "Konuşmalar: sıralama sütunu"),
            (
                &[
                    A::SelectTab(0),
                    A::SelectTab(1),
                    A::SelectTab(2),
                    A::SelectTab(3),
                ],
                "İstatistik alt sekmesi",
            ),
            (&[A::ToggleResolve], "DNS ad çözümleme aç/kapa"),
        ],
    },
    Group {
        title: "Filtre ve komut",
        entries: &[
            (&[A::Filter], "display filter (Tab, ↑↓ geçmiş)"),
            (&[A::Command], "komut paleti (:w :theme ...)"),
        ],
    },
    Group {
        title: "Yakalama ve genel",
        entries: &[
            (&[A::Pause], "yakalamayı duraklat / devam"),
            (&[A::AutoScroll], "otomatik kaydırma"),
            (&[A::Help], "bu yardım"),
            (&[A::Quit], "çık (ek görünümde: geri)"),
        ],
    },
];

/// Gerçek keymap'ten tuş metni (config atamalarını yansıtır).
fn keys_text(app: &App, actions: &[Action]) -> String {
    if let [a] = actions {
        let keys = app.keymap.keys_for(*a);
        if keys.is_empty() {
            return "(atanmamış)".into();
        }
        keys.into_iter()
            .map(format_key)
            .collect::<Vec<_>>()
            .join(" / ")
    } else {
        actions
            .iter()
            .map(|&a| app.key_hint(a))
            .collect::<Vec<_>>()
            .join(" ")
    }
}

fn group_lines(app: &App, g: &Group, key_w: usize) -> Vec<Line<'static>> {
    let t = &app.theme;
    let mut v = vec![Line::styled(
        g.title,
        Style::default()
            .fg(t.accent)
            .add_modifier(Modifier::BOLD | Modifier::UNDERLINED),
    )];
    for (actions, desc) in g.entries {
        v.push(Line::from(vec![
            Span::styled(
                format!("{:<key_w$} ", keys_text(app, actions)),
                Style::default().fg(t.warn).add_modifier(Modifier::BOLD),
            ),
            Span::raw(*desc),
        ]));
    }
    v
}

/// Ortalanmış yardım penceresi: gruplar iki sütunda; tuşlar gerçek keymap'ten.
pub(crate) fn draw_help(f: &mut Frame, app: &App) {
    let t = &app.theme;
    let area = f.area();
    let key_w = GROUPS
        .iter()
        .flat_map(|g| g.entries.iter())
        .map(|(a, _)| keys_text(app, a).chars().count())
        .max()
        .unwrap_or(8)
        .min(22);
    let col_w = key_w + 1 + 34;
    let mut cols: [Vec<Line>; 2] = [Vec::new(), Vec::new()];
    for g in GROUPS {
        let i = usize::from(cols[0].len() > cols[1].len());
        if !cols[i].is_empty() {
            cols[i].push(Line::raw(""));
        }
        cols[i].extend(group_lines(app, g, key_w));
    }
    let rows = cols[0].len().max(cols[1].len());
    let w = u16::try_from(col_w * 2 + 7)
        .unwrap_or(u16::MAX)
        .min(area.width);
    let h = u16::try_from(rows + 4).unwrap_or(u16::MAX).min(area.height);
    let r = Rect::new(
        area.x + (area.width - w) / 2,
        area.y + (area.height - h) / 2,
        w,
        h,
    );
    f.render_widget(Clear, r);
    let block = panel_block(" Yardım ", true, t).style(Style::default().fg(t.fg).bg(t.toast_bg));
    let inner = block.inner(r);
    f.render_widget(block, r);
    let inner = inner.inner(Margin::new(1, 0));
    let [body, foot] = Layout::vertical([Constraint::Fill(1), Constraint::Length(1)]).areas(inner);
    let [c0, gap, c1] = Layout::horizontal([
        Constraint::Percentage(50),
        Constraint::Length(2),
        Constraint::Percentage(50),
    ])
    .areas(body);
    let _ = gap;
    let [c0, c1] = [c0, c1];
    let [l0, l1] = cols;
    f.render_widget(Paragraph::new(l0), c0);
    f.render_widget(Paragraph::new(l1), c1);
    f.render_widget(
        Paragraph::new(format!(
            "fare: tıkla seç, tekerlek kaydır · {} / {} / {} ile kapat",
            "Esc",
            app.key_hint(Action::Help),
            app.key_hint(Action::Quit)
        ))
        .style(Style::default().fg(t.dim))
        .alignment(Alignment::Center),
        foot,
    );
}
