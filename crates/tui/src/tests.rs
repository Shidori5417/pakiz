use std::collections::{HashSet, VecDeque};
use std::time::{Duration, SystemTime};

use pakiz_dissect::RawPacket;
use ratatui::backend::TestBackend;
use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::Terminal;

use super::*;

/// eth + ipv4 + udp (10.0.0.1:1234 → 10.0.0.2:53), 4 bayt yük.
fn udp_packet(i: u32) -> RawPacket {
    let mut d = vec![
        0, 1, 2, 3, 4, 5, 0, 1, 2, 3, 4, 6, 0x08, 0x00, // eth
        0x45, 0, 0, 32, 0, 1, 0, 0, 64, 17, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2, // ipv4
        0x04, 0xd2, 0x00, 0x35, 0, 12, 0, 0, // udp
    ];
    d.extend_from_slice(b"abcd");
    RawPacket {
        ts: SystemTime::UNIX_EPOCH + Duration::from_millis(u64::from(i) * 10),
        orig_len: u32::try_from(d.len()).unwrap(),
        data: d,
        ifindex: 1,
    }
}

fn app_with(n: u32, max: usize) -> App {
    let src = VecSource {
        name: "test0".into(),
        packets: (0..n).map(udp_packet).collect::<VecDeque<_>>(),
    };
    let mut app = App::new(Box::new(src), max);
    app.ingest();
    app
}

fn screen(app: &mut App, w: u16, h: u16) -> String {
    let mut t = Terminal::new(TestBackend::new(w, h)).unwrap();
    t.draw(|f| draw(f, app)).unwrap();
    let buf = t.backend().buffer().clone();
    (0..h)
        .map(|y| {
            (0..w)
                .map(|x| buf[(x, y)].symbol().to_string())
                .collect::<String>()
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn list_renders_only_visible_rows() {
    let mut app = app_with(500, 1000);
    let s = screen(&mut app, 120, 40);
    assert!(s.contains("Paketler") && s.contains("Katmanlar") && s.contains("Hex"));
    assert!(s.contains("10.0.0.1") && s.contains("UDP"));
    // Otomatik kaydırma: son paket görünür, ilk paket değil.
    assert!(s.contains(" 500 "));
    assert!(!s.lines().any(|l| l.starts_with("│1 ")));
    assert!(s.contains("toplam: 500"));
    assert!(s.contains("AUTOSCROLL"));
}

#[test]
fn ring_buffer_overflow_drops_oldest() {
    let app = app_with(10, 4);
    assert_eq!(app.store.len(), 4);
    assert_eq!(app.store.total(), 10);
    assert_eq!(app.store.evicted(), 6);
    assert_eq!(app.store.get(0).unwrap().number, 7);
    assert_eq!(app.dropped(), 6);
    assert_eq!(app.selected, Some(3));
}

#[test]
fn pause_queues_packets() {
    let mut src = VecSource::default();
    src.packets.push_back(udp_packet(0));
    let mut app = App::new(Box::new(src), 100);
    app.apply(Action::Pause);
    app.ingest();
    assert_eq!(app.store.len(), 0);
    assert_eq!(app.pending_len(), 1);
    app.apply(Action::Pause);
    app.ingest();
    assert_eq!(app.store.len(), 1);
    assert_eq!(app.pending_len(), 0);
}

#[test]
fn highlight_range_clips() {
    assert_eq!(highlight_range(14, 20, 46), Some(14..34));
    assert_eq!(highlight_range(40, 20, 46), Some(40..46));
    assert_eq!(highlight_range(50, 4, 46), None);
    assert_eq!(highlight_range(3, 0, 46), None);
}

#[test]
fn hex_line_highlights_selected_bytes() {
    let theme = Theme::default();
    let data: Vec<u8> = (0..40).collect();
    let line = hex_line(&data, 1, Some(&(18..20)), &theme);
    let hl: Vec<String> = line
        .spans
        .iter()
        .filter(|s| s.style.bg == Some(theme.hex_highlight_bg))
        .map(|s| s.content.to_string())
        .collect();
    // 0x12, 0x13 hex + ASCII karşılıkları ('.' kontrol karakterleri).
    assert_eq!(hl, vec!["12", "13", ".", "."]);
    assert!(line.spans[0].content.starts_with("0010"));
}

#[test]
fn tree_expand_and_hex_follow() {
    let mut app = app_with(1, 10);
    app.apply(Action::NextPanel);
    assert_eq!(app.focus, Panel::Tree);
    let collapsed = app.tree().unwrap().1.len();
    assert_eq!(collapsed, 5); // frame, eth, ipv4, udp, data
    app.apply(Action::Bottom);
    app.apply(Action::Up); // udp
    app.apply(Action::Expand);
    let rows = app.tree().unwrap().1.to_vec();
    assert!(rows.len() > collapsed);
    assert!(rows[3].expanded && rows[3].label.contains("User Datagram"));
    app.apply(Action::Down); // udp'nin ilk alanı (srcport)
    let r = app.selected_row().unwrap();
    assert_eq!((r.offset, r.len), (34, 2));
    app.apply(Action::Collapse); // yaprakta etkisiz
    app.apply(Action::Up);
    app.apply(Action::Toggle);
    assert_eq!(app.tree().unwrap().1.len(), collapsed);
    let _ = flatten(app.tree().unwrap().0, &HashSet::new());
}

#[test]
fn keymap_defaults() {
    let km = Keymap::default();
    let k = |c, m| km.action(&KeyEvent::new(c, m));
    assert_eq!(
        k(KeyCode::Char('j'), KeyModifiers::NONE),
        Some(Action::Down)
    );
    assert_eq!(
        k(KeyCode::Char('d'), KeyModifiers::CONTROL),
        Some(Action::HalfPageDown)
    );
    assert_eq!(
        k(KeyCode::Char('G'), KeyModifiers::SHIFT),
        Some(Action::Bottom)
    );
    assert_eq!(k(KeyCode::Tab, KeyModifiers::NONE), Some(Action::NextPanel));
    assert_eq!(k(KeyCode::Char('x'), KeyModifiers::NONE), None);
}

#[test]
fn input_line_keeps_text_and_help_overlay() {
    let mut app = app_with(3, 10);
    app.on_key(KeyEvent::new(KeyCode::Char('/'), KeyModifiers::NONE));
    for c in "tcp".chars() {
        app.on_key(KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE));
    }
    let s = screen(&mut app, 100, 30);
    assert!(s.contains("/tcp"));
    app.on_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
    assert_eq!(app.filter_text, "tcp");
    assert!(app.input.is_none());
    app.on_key(KeyEvent::new(KeyCode::Char('?'), KeyModifiers::NONE));
    assert!(screen(&mut app, 100, 30).contains("Yardım"));
}

#[test]
fn protocol_colors() {
    let t = Theme::default();
    assert_eq!(t.protocol_color("TCP", false), t.tcp);
    assert_eq!(t.protocol_color("UDP", true), t.malformed);
    assert_eq!(t.protocol_color("ARP", false), t.arp);
}
