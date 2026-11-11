//! Ek görünümler: Follow Stream, Konuşmalar, İstatistik (durum + çizim).

use std::fmt::Write as _;
use std::net::SocketAddr;
use std::ops::Range;
use std::time::{Duration, Instant};

use pakiz_flow::{render_ascii, Chunk, Conversation, Dir, Proto, Stream, StreamId, TcpState};
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::Line;
use ratatui::widgets::{Block, Borders, Cell, Paragraph, Row, Sparkline, Table, Tabs};
use ratatui::Frame;

use crate::analyzer::Analyzer;
use crate::app::App;
use crate::theme::Theme;

/// Etkin görünüm (üst sekme çubuğu).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum View {
    #[default]
    Packets,
    Follow,
    Conversations,
    Stats,
}

impl View {
    pub const ALL: [View; 4] = [
        View::Packets,
        View::Follow,
        View::Conversations,
        View::Stats,
    ];

    #[must_use]
    pub fn title(self) -> &'static str {
        match self {
            View::Packets => "Paketler",
            View::Follow => "Akış [F]",
            View::Conversations => "Konuşmalar [c]",
            View::Stats => "İstatistik [S]",
        }
    }
}

/// Follow Stream gösterim kipi.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FollowMode {
    #[default]
    Ascii,
    Hex,
    Raw,
}

impl FollowMode {
    #[must_use]
    pub fn next(self) -> Self {
        match self {
            Self::Ascii => Self::Hex,
            Self::Hex => Self::Raw,
            Self::Raw => Self::Ascii,
        }
    }

    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Ascii => "ASCII",
            Self::Hex => "Hex",
            Self::Raw => "Raw",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct LayoutKey {
    chunks: usize,
    stored: [usize; 2],
    dropped: [u64; 2],
    mode: FollowMode,
    width: usize,
}

/// Parça başına satır başlangıçları (yalnızca akış değişince yeniden hesaplanır).
#[derive(Debug, Clone)]
struct FollowLayout {
    key: LayoutKey,
    /// `starts[i]` = i. parçanın ilk satırı; son eleman toplam satır.
    starts: Vec<usize>,
    /// Parçanın kendi yönündeki bayt ofseti (hex kipinde ofset sütunu).
    bases: Vec<u64>,
}

/// Follow Stream görünümü durumu.
#[derive(Debug, Clone)]
pub struct FollowView {
    pub stream: StreamId,
    pub mode: FollowMode,
    /// İlk görünen satır.
    pub offset: usize,
    layout: Option<FollowLayout>,
    /// Son çizimdeki toplam satır ve içerik yüksekliği (kaydırma sınırı).
    pub(crate) total: usize,
    pub(crate) height: usize,
}

impl FollowView {
    #[must_use]
    pub fn new(stream: StreamId) -> Self {
        Self {
            stream,
            mode: FollowMode::Ascii,
            offset: 0,
            layout: None,
            total: 0,
            height: 0,
        }
    }

    /// `delta` satır kaydırır (sınırlar: 0 ..= toplam - yükseklik).
    pub(crate) fn scroll(&mut self, delta: isize) {
        let max = self.total.saturating_sub(self.height.max(1));
        self.offset = self.offset.saturating_add_signed(delta).min(max);
    }
}

/// Konuşma tablosu sıralama sütunu.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ConvSort {
    #[default]
    Stream,
    Packets,
    Bytes,
    Duration,
}

impl ConvSort {
    #[must_use]
    pub fn next(self) -> Self {
        match self {
            Self::Stream => Self::Packets,
            Self::Packets => Self::Bytes,
            Self::Bytes => Self::Duration,
            Self::Duration => Self::Stream,
        }
    }

    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Stream => "akış",
            Self::Packets => "paket",
            Self::Bytes => "bayt",
            Self::Duration => "süre",
        }
    }
}

/// Konuşmalar görünümü durumu.
#[derive(Debug, Clone, Default)]
pub struct ConvView {
    pub rows: Vec<Conversation>,
    pub selected: usize,
    pub offset: usize,
    pub sort: ConvSort,
    /// Son anlık görüntü zamanı (`None` = bir sonraki çizimde yenile).
    pub(crate) refreshed: Option<Instant>,
    pub(crate) height: usize,
}

impl ConvView {
    /// Akış tablosundan yeniden doldurur ve sıralar (seçili akış korunur).
    pub(crate) fn refresh(&mut self, rows: Vec<Conversation>) {
        let keep = self.rows.get(self.selected).map(|c| c.stream);
        self.rows = rows;
        self.sort_rows();
        if let Some(id) = keep {
            if let Some(i) = self.rows.iter().position(|c| c.stream == id) {
                self.selected = i;
            }
        }
        self.selected = self.selected.min(self.rows.len().saturating_sub(1));
        self.refreshed = Some(Instant::now());
    }

    pub(crate) fn sort_rows(&mut self) {
        let total = |c: &Conversation, f: fn(&Conversation) -> [u64; 2]| {
            let v = f(c);
            v[0] + v[1]
        };
        match self.sort {
            ConvSort::Stream => self.rows.sort_by_key(|c| c.stream),
            ConvSort::Packets => self
                .rows
                .sort_by_key(|c| std::cmp::Reverse(total(c, |c| c.packets))),
            ConvSort::Bytes => self
                .rows
                .sort_by_key(|c| std::cmp::Reverse(total(c, |c| c.bytes))),
            ConvSort::Duration => self.rows.sort_by_key(|c| std::cmp::Reverse(c.duration)),
        }
    }

    pub(crate) fn move_by(&mut self, delta: isize) {
        if self.rows.is_empty() {
            return;
        }
        self.selected = self
            .selected
            .saturating_add_signed(delta)
            .min(self.rows.len() - 1);
    }
}

/// İstatistik alt sekmesi.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum StatsTab {
    #[default]
    Hierarchy,
    Talkers,
    IpConversations,
    Ports,
}

impl StatsTab {
    pub const ALL: [StatsTab; 4] = [
        StatsTab::Hierarchy,
        StatsTab::Talkers,
        StatsTab::IpConversations,
        StatsTab::Ports,
    ];

    #[must_use]
    pub fn title(self) -> &'static str {
        match self {
            Self::Hierarchy => "1 Protokol hiyerarşisi",
            Self::Talkers => "2 Top talkers",
            Self::IpConversations => "3 IP konuşmaları",
            Self::Ports => "4 Port dağılımı",
        }
    }

    #[must_use]
    pub fn next(self) -> Self {
        let i = Self::ALL.iter().position(|&t| t == self).unwrap_or(0);
        Self::ALL[(i + 1) % Self::ALL.len()]
    }
}

/// İstatistik görünümü durumu.
#[derive(Debug, Clone, Default)]
pub struct StatsView {
    pub tab: StatsTab,
    /// Tablonun ilk görünen satırı.
    pub offset: usize,
    pub(crate) rows: usize,
    pub(crate) height: usize,
}

impl StatsView {
    pub(crate) fn scroll(&mut self, delta: isize) {
        let max = self.rows.saturating_sub(self.height.max(1));
        self.offset = self.offset.saturating_add_signed(delta).min(max);
    }
}

/// Tablolarda kaç satıra kadar veri hazırlanır.
const STATS_ROWS: usize = 1000;

// ------------------------------------------------------------------ yardımcılar

/// `1.5 KB` biçimi (1024 tabanı).
#[must_use]
#[allow(clippy::cast_precision_loss)]
pub fn fmt_bytes(n: u64) -> String {
    const U: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut v = n as f64;
    let mut i = 0;
    while v >= 1024.0 && i < U.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{n} B")
    } else {
        format!("{v:.1} {}", U[i])
    }
}

fn fmt_dur(d: Duration) -> String {
    format!("{:.3}s", d.as_secs_f64())
}

/// `n` açıkken IP yerine DNS adı.
fn addr(an: &Analyzer, ip: std::net::IpAddr, resolve: bool) -> String {
    match an.name_for(ip).filter(|_| resolve) {
        Some(n) => n.to_owned(),
        None => ip.to_string(),
    }
}

fn sock(an: &Analyzer, s: SocketAddr, resolve: bool) -> String {
    match an.name_for(s.ip()).filter(|_| resolve) {
        Some(n) => format!("{n}:{}", s.port()),
        None => s.to_string(),
    }
}

fn state_name(s: Option<TcpState>) -> &'static str {
    match s {
        None => "-",
        Some(TcpState::SynSent) => "SYN gönderildi",
        Some(TcpState::Established) => "Kurulu",
        Some(TcpState::Closed) => "Kapandı",
        Some(TcpState::Reset) => "RST",
    }
}

fn titled<'a>(title: impl Into<Line<'a>>, theme: &Theme) -> Block<'a> {
    Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme.border_focus))
        .title(title)
}

fn header_style() -> Style {
    Style::default().add_modifier(Modifier::BOLD | Modifier::UNDERLINED)
}

#[allow(clippy::cast_precision_loss)]
fn pct(part: u64, total: u64) -> String {
    if total == 0 {
        return "-".into();
    }
    format!("{:.1}%", part as f64 * 100.0 / total as f64)
}

// ------------------------------------------------------------------ Follow

/// Bir parçanın ASCII kipindeki satırları (`\n`'de ve `width`'te bölünür;
/// satır aralıkları `\n` içermez).
fn ascii_lines(data: &[u8], width: usize) -> impl Iterator<Item = Range<usize>> + '_ {
    let width = width.max(1);
    let mut pos = 0;
    std::iter::from_fn(move || {
        if pos >= data.len() {
            return None;
        }
        let start = pos;
        let mut col = 0;
        while let Some(&b) = data.get(pos) {
            if b == b'\n' {
                pos += 1;
                return Some(start..pos - 1);
            }
            pos += 1;
            if b != b'\r' {
                col += 1;
            }
            if col == width {
                if data.get(pos) == Some(&b'\n') {
                    pos += 1;
                    return Some(start..pos - 1);
                }
                return Some(start..pos);
            }
        }
        Some(start..pos)
    })
}

fn raw_per_line(width: usize) -> usize {
    (width / 2).max(1)
}

fn chunk_lines(c: &Chunk<'_>, mode: FollowMode, width: usize) -> usize {
    if c.marker.is_some() {
        return 1;
    }
    match mode {
        FollowMode::Ascii => ascii_lines(c.data, width).count().max(1),
        FollowMode::Hex => c.data.len().div_ceil(16).max(1),
        FollowMode::Raw => c.data.len().div_ceil(raw_per_line(width)).max(1),
    }
}

fn layout_key(s: &Stream, mode: FollowMode, width: usize) -> LayoutKey {
    LayoutKey {
        chunks: s.chunks().count(),
        stored: [s.stored_bytes(Dir::Client), s.stored_bytes(Dir::Server)],
        dropped: [s.dropped_bytes(Dir::Client), s.dropped_bytes(Dir::Server)],
        mode,
        width,
    }
}

fn build_layout(s: &Stream, key: LayoutKey) -> FollowLayout {
    let mut starts = Vec::with_capacity(key.chunks + 1);
    let mut bases = Vec::with_capacity(key.chunks);
    let mut line = 0;
    let mut dir_off = [0u64; 2];
    for c in s.chunks() {
        starts.push(line);
        bases.push(dir_off[c.dir.index()]);
        dir_off[c.dir.index()] += c.data.len() as u64;
        line += chunk_lines(&c, key.mode, key.width);
    }
    starts.push(line);
    FollowLayout { key, starts, bases }
}

fn ascii_text(data: &[u8]) -> String {
    data.iter()
        .filter(|&&b| b != b'\r' && b != b'\n')
        .map(|&b| match b {
            b'\t' => ' ',
            b if b.is_ascii_graphic() || b == b' ' => char::from(b),
            _ => '.',
        })
        .collect()
}

fn hex_text(data: &[u8], base: u64) -> String {
    let mut s = format!("{base:08x}  ");
    for j in 0..16 {
        match data.get(j) {
            Some(b) => {
                let _ = write!(s, "{b:02x} ");
            }
            None => s.push_str("   "),
        }
        if j == 7 {
            s.push(' ');
        }
    }
    s.push(' ');
    s.extend(data.iter().map(|&b| {
        if b.is_ascii_graphic() || b == b' ' {
            char::from(b)
        } else {
            '.'
        }
    }));
    s
}

/// Parçanın `line`. satırının metni.
fn chunk_line(c: &Chunk<'_>, mode: FollowMode, width: usize, base: u64, line: usize) -> String {
    if c.marker.is_some() {
        return render_ascii(c);
    }
    match mode {
        FollowMode::Ascii => ascii_lines(c.data, width)
            .nth(line)
            .map(|r| ascii_text(c.data.get(r).unwrap_or_default()))
            .unwrap_or_default(),
        FollowMode::Hex => {
            let s = line * 16;
            let e = (s + 16).min(c.data.len());
            hex_text(c.data.get(s..e).unwrap_or_default(), base + s as u64)
        }
        FollowMode::Raw => {
            let per = raw_per_line(width);
            let s = line * per;
            let e = (s + per).min(c.data.len());
            let mut out = String::new();
            for b in c.data.get(s..e).unwrap_or_default() {
                let _ = write!(out, "{b:02x}");
            }
            out
        }
    }
}

fn dir_color(theme: &Theme, d: Dir) -> ratatui::style::Color {
    match d {
        Dir::Client => theme.follow_client,
        Dir::Server => theme.follow_server,
    }
}

#[allow(clippy::too_many_lines)]
pub(crate) fn draw_follow(f: &mut Frame, app: &mut App, area: Rect) {
    let App {
        analyzer,
        follow,
        theme,
        resolve_names,
        ..
    } = app;
    let Some(fv) = follow.as_mut() else {
        f.render_widget(
            Paragraph::new("Akış seçilmedi: paket listesinde TCP/UDP paketi seçip F'ye basın.")
                .block(titled(" Follow Stream ", theme)),
            area,
        );
        return;
    };
    let [head, body] = Layout::vertical([Constraint::Length(5), Constraint::Min(3)]).areas(area);
    let proto = if fv.stream.proto == Proto::Tcp {
        "TCP"
    } else {
        "UDP"
    };
    let title = format!(
        " Follow {proto} Stream ({}) — kip: {} [m] ",
        fv.stream,
        fv.mode.name()
    );
    let conv = analyzer.flows.conversation(fv.stream);
    let head_lines: Vec<Line> = match &conv {
        Some(c) => {
            let (cl, sv) = (
                sock(analyzer, c.client, *resolve_names),
                sock(analyzer, c.server, *resolve_names),
            );
            vec![
                Line::from(format!(
                    "{proto} {cl} ↔ {sv}   süre: {}   durum: {}",
                    fmt_dur(c.duration),
                    state_name(c.state)
                )),
                Line::styled(
                    format!(
                        "■ istemci {cl} → {sv}: {} paket, {}",
                        c.packets[0],
                        fmt_bytes(c.bytes[0])
                    ),
                    Style::default().fg(theme.follow_client),
                ),
                Line::styled(
                    format!(
                        "■ sunucu  {sv} → {cl}: {} paket, {}",
                        c.packets[1],
                        fmt_bytes(c.bytes[1])
                    ),
                    Style::default().fg(theme.follow_server),
                ),
            ]
        }
        None => vec![Line::from(
            "akış bellekte yok (zaman aşımı/LRU ile atılmış)",
        )],
    };
    f.render_widget(Paragraph::new(head_lines).block(titled(title, theme)), head);

    let width = usize::from(body.width.saturating_sub(2)).max(1);
    let height = usize::from(body.height.saturating_sub(2));
    let Some(stream) = analyzer.flows.stream(fv.stream) else {
        f.render_widget(Paragraph::new("").block(titled(" İçerik ", theme)), body);
        return;
    };
    let key = layout_key(stream, fv.mode, width);
    if fv.layout.as_ref().is_none_or(|l| l.key != key) {
        fv.layout = Some(build_layout(stream, key));
    }
    let Some(lay) = fv.layout.as_ref() else {
        return;
    };
    let total = lay.starts.last().copied().unwrap_or(0);
    fv.total = total;
    fv.height = height;
    fv.offset = fv.offset.min(total.saturating_sub(height.max(1)));
    let mut lines = Vec::with_capacity(height);
    // Yalnızca görünen satırlar: ilk parçayı ikili aramayla bul.
    let mut ci = lay
        .starts
        .partition_point(|&s| s <= fv.offset)
        .saturating_sub(1);
    let mut l = fv.offset - lay.starts.get(ci).copied().unwrap_or(0);
    let mut chunks = stream.chunks().skip(ci);
    let mut cur = chunks.next();
    while lines.len() < height {
        let Some(c) = cur else { break };
        let n = lay.starts[ci + 1] - lay.starts[ci];
        if l >= n {
            ci += 1;
            l = 0;
            cur = chunks.next();
            continue;
        }
        let text = chunk_line(&c, fv.mode, width, lay.bases[ci], l);
        let mut st = Style::default().fg(dir_color(theme, c.dir));
        if c.marker.is_some() {
            st = st.add_modifier(Modifier::BOLD | Modifier::ITALIC);
        }
        lines.push(Line::styled(text, st));
        l += 1;
    }
    let pos = if total == 0 {
        " İçerik (boş) ".to_string()
    } else {
        format!(
            " İçerik [{}-{}/{total}] (j/k g/G kaydır, Esc geri) ",
            fv.offset + 1,
            (fv.offset + height).min(total)
        )
    };
    f.render_widget(Paragraph::new(lines).block(titled(pos, theme)), body);
}

// ------------------------------------------------------------------ Konuşmalar

pub(crate) fn draw_conversations(f: &mut Frame, app: &mut App, area: Rect) {
    let stale = app
        .conv
        .refreshed
        .is_none_or(|t| t.elapsed() >= Duration::from_secs(1));
    if stale {
        let rows = app.analyzer.flows.conversations();
        app.conv.refresh(rows);
    }
    let App {
        analyzer,
        conv,
        theme,
        resolve_names,
        ..
    } = app;
    let visible = usize::from(area.height.saturating_sub(3));
    conv.height = visible.max(1);
    if conv.selected < conv.offset {
        conv.offset = conv.selected;
    } else if visible > 0 && conv.selected >= conv.offset + visible {
        conv.offset = conv.selected + 1 - visible;
    }
    let sel = conv.selected;
    let rows = conv
        .rows
        .iter()
        .enumerate()
        .skip(conv.offset)
        .take(visible)
        .map(|(i, c)| {
            let mut st = Style::default().fg(match c.key.proto {
                Proto::Tcp => theme.tcp,
                Proto::Udp => theme.udp,
            });
            if i == sel {
                st = st.bg(theme.selected_bg).add_modifier(Modifier::BOLD);
            }
            Row::new(vec![
                Cell::from(c.stream.index.to_string()),
                Cell::from(c.key.proto.to_string()),
                Cell::from(sock(analyzer, c.client, *resolve_names)),
                Cell::from(sock(analyzer, c.server, *resolve_names)),
                Cell::from(c.packets[0].to_string()),
                Cell::from(fmt_bytes(c.bytes[0])),
                Cell::from(c.packets[1].to_string()),
                Cell::from(fmt_bytes(c.bytes[1])),
                Cell::from(fmt_dur(c.duration)),
                Cell::from(state_name(c.state)),
            ])
            .style(st)
        });
    let mark = |s: ConvSort, t: &'static str| -> String {
        if conv.sort == s {
            format!("{t}▼")
        } else {
            t.to_string()
        }
    };
    let header = Row::new(vec![
        mark(ConvSort::Stream, "Akış"),
        "Proto".into(),
        "A (istemci)".into(),
        "B (sunucu)".into(),
        mark(ConvSort::Packets, "Pkt A→B"),
        mark(ConvSort::Bytes, "Bayt A→B"),
        "Pkt B→A".into(),
        "Bayt B→A".into(),
        mark(ConvSort::Duration, "Süre"),
        "Durum".into(),
    ])
    .style(header_style());
    let widths = [
        Constraint::Length(6),
        Constraint::Length(5),
        Constraint::Fill(1),
        Constraint::Fill(1),
        Constraint::Length(8),
        Constraint::Length(10),
        Constraint::Length(8),
        Constraint::Length(10),
        Constraint::Length(9),
        Constraint::Length(14),
    ];
    let title = format!(
        " Konuşmalar ({}) — s: sırala [{}], Enter: akışa filtrele, Esc: geri ",
        conv.rows.len(),
        conv.sort.name()
    );
    f.render_widget(
        Table::new(rows, widths)
            .header(header)
            .block(titled(title, theme)),
        area,
    );
}

// ------------------------------------------------------------------ İstatistik

#[allow(
    clippy::too_many_lines,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]
pub(crate) fn draw_stats(f: &mut Frame, app: &mut App, area: Rect) {
    let App {
        analyzer,
        stats_view: sv,
        theme,
        resolve_names,
        ..
    } = app;
    let st = &analyzer.stats;
    let [graphs, tabs, table] = Layout::vertical([
        Constraint::Length(7),
        Constraint::Length(1),
        Constraint::Min(3),
    ])
    .areas(area);
    let [g1, g2] =
        Layout::horizontal([Constraint::Percentage(50), Constraint::Percentage(50)]).areas(graphs);
    let (avg_p, avg_b) = st.average();
    let peak = st.peak();
    for (r, series, title, color) in [
        (
            g1,
            st.pps_series(),
            format!(
                " Paket/sn — son {} · tepe {} · ort {avg_p:.1} ",
                st.pps_series().last().copied().unwrap_or(0),
                peak.packets
            ),
            theme.udp,
        ),
        (
            g2,
            st.bps_series(),
            format!(
                " Bayt/sn — son {} · tepe {} · ort {}/s ",
                fmt_bytes(st.bps_series().last().copied().unwrap_or(0)),
                fmt_bytes(peak.bytes),
                fmt_bytes(avg_b as u64)
            ),
            theme.tcp,
        ),
    ] {
        let w = usize::from(r.width.saturating_sub(2));
        let tail = &series[series.len().saturating_sub(w)..];
        f.render_widget(
            Sparkline::default()
                .block(titled(title, theme))
                .data(tail)
                .style(Style::default().fg(color)),
            r,
        );
    }
    let idx = StatsTab::ALL.iter().position(|&t| t == sv.tab).unwrap_or(0);
    f.render_widget(
        Tabs::new(StatsTab::ALL.iter().map(|t| t.title()))
            .select(idx)
            .highlight_style(
                Style::default()
                    .fg(theme.border_focus)
                    .add_modifier(Modifier::BOLD | Modifier::REVERSED),
            ),
        tabs,
    );

    let total = st.total();
    let (header, widths, rows): (Vec<&str>, Vec<Constraint>, Vec<Vec<String>>) = match sv.tab {
        StatsTab::Hierarchy => (
            vec!["Protokol", "Paket", "% Paket", "Bayt", "% Bayt"],
            vec![
                Constraint::Fill(1),
                Constraint::Length(10),
                Constraint::Length(9),
                Constraint::Length(11),
                Constraint::Length(9),
            ],
            st.protocol_hierarchy()
                .into_iter()
                .map(|n| {
                    vec![
                        format!("{}{}", "  ".repeat(n.depth), n.protocol),
                        n.counter.packets.to_string(),
                        pct(n.counter.packets, total.packets),
                        fmt_bytes(n.counter.bytes),
                        pct(n.counter.bytes, total.bytes),
                    ]
                })
                .collect(),
        ),
        StatsTab::Talkers => (
            vec![
                "Adres",
                "Ad (DNS)",
                "Gön. pkt",
                "Gön. bayt",
                "Alı. pkt",
                "Alı. bayt",
            ],
            vec![
                Constraint::Length(28),
                Constraint::Fill(1),
                Constraint::Length(9),
                Constraint::Length(10),
                Constraint::Length(9),
                Constraint::Length(10),
            ],
            st.top_talkers(STATS_ROWS)
                .into_iter()
                .map(|(ip, t)| {
                    vec![
                        ip.to_string(),
                        analyzer.name_for(ip).unwrap_or("-").to_owned(),
                        t.tx.packets.to_string(),
                        fmt_bytes(t.tx.bytes),
                        t.rx.packets.to_string(),
                        fmt_bytes(t.rx.bytes),
                    ]
                })
                .collect(),
        ),
        StatsTab::IpConversations => (
            vec![
                "A",
                "B",
                "Pkt A→B",
                "Bayt A→B",
                "Pkt B→A",
                "Bayt B→A",
                "Süre",
            ],
            vec![
                Constraint::Fill(1),
                Constraint::Fill(1),
                Constraint::Length(9),
                Constraint::Length(10),
                Constraint::Length(9),
                Constraint::Length(10),
                Constraint::Length(10),
            ],
            st.top_ip_conversations(STATS_ROWS)
                .into_iter()
                .map(|c| {
                    vec![
                        addr(analyzer, c.a, *resolve_names),
                        addr(analyzer, c.b, *resolve_names),
                        c.a_to_b.packets.to_string(),
                        fmt_bytes(c.a_to_b.bytes),
                        c.b_to_a.packets.to_string(),
                        fmt_bytes(c.b_to_a.bytes),
                        fmt_dur(c.last.duration_since(c.first).unwrap_or_default()),
                    ]
                })
                .collect(),
        ),
        StatsTab::Ports => (
            vec!["Proto", "Hedef port", "Paket", "Bayt", "% Bayt"],
            vec![
                Constraint::Length(6),
                Constraint::Length(11),
                Constraint::Length(10),
                Constraint::Length(11),
                Constraint::Fill(1),
            ],
            st.top_ports(STATS_ROWS)
                .into_iter()
                .map(|(t, p, c)| {
                    vec![
                        format!("{t:?}").to_uppercase(),
                        p.to_string(),
                        c.packets.to_string(),
                        fmt_bytes(c.bytes),
                        pct(c.bytes, total.bytes),
                    ]
                })
                .collect(),
        ),
    };
    let visible = usize::from(table.height.saturating_sub(3));
    sv.rows = rows.len();
    sv.height = visible.max(1);
    sv.offset = sv.offset.min(rows.len().saturating_sub(visible.max(1)));
    let n = rows.len();
    let body = rows
        .into_iter()
        .skip(sv.offset)
        .take(visible)
        .map(|r| Row::new(r.into_iter().map(Cell::from)));
    let title = format!(
        " {} — {n} satır · toplam {} paket, {} (Tab/1-4 sekme, j/k kaydır) ",
        sv.tab.title(),
        total.packets,
        fmt_bytes(total.bytes)
    );
    f.render_widget(
        Table::new(body, widths)
            .header(Row::new(header).style(header_style()))
            .block(titled(title, theme)),
        table,
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ascii_lines_split_and_wrap() {
        let d = b"GET / HTTP/1.1\r\nHost: x\r\n\r\nabcdefgh";
        let v: Vec<String> = ascii_lines(d, 100).map(|r| ascii_text(&d[r])).collect();
        assert_eq!(v, ["GET / HTTP/1.1", "Host: x", "", "abcdefgh"]);
        let v: Vec<String> = ascii_lines(b"abcdef\nxy", 3)
            .map(|r| ascii_text(&b"abcdef\nxy"[r]))
            .collect();
        assert_eq!(v, ["abc", "def", "xy"]);
        assert_eq!(fmt_bytes(1536), "1.5 KB");
        assert_eq!(fmt_bytes(12), "12 B");
    }
}
