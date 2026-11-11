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
    assert!(s.contains("│500 "));
    assert!(!s.lines().any(|l| l.starts_with("│1 ")));
    assert!(s.contains("gösterilen/toplam: 500/500"));
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

fn tmp_path(ext: &str) -> std::path::PathBuf {
    use std::sync::atomic::{AtomicU32, Ordering};
    static N: AtomicU32 = AtomicU32::new(0);
    let n = N.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!("pakiz-tui-{}-{n}.{ext}", std::process::id()))
}

fn write_file(n: u32, ext: &str) -> std::path::PathBuf {
    let p = tmp_path(ext);
    let mut w = pakiz_storage::create(&p, pakiz_storage::Format::from_path(&p)).unwrap();
    for i in 0..n {
        w.write_packet(&udp_packet(i)).unwrap();
    }
    w.flush().unwrap();
    p
}

fn count_packets(p: &std::path::Path) -> usize {
    let mut r = pakiz_storage::CaptureReader::open(p).unwrap();
    let mut n = 0;
    while r.next_packet().unwrap().is_some() {
        n += 1;
    }
    n
}

#[test]
fn file_source_indexes_incrementally_and_reads_lazily() {
    let n = u32::try_from(INDEX_BATCH).unwrap() * 2 + 5;
    let path = write_file(n, "pcap");
    let file = pakiz_storage::IndexedFile::open(&path).unwrap();
    let mut app = App::from_file(file, "dosya.pcap");
    assert!(app.store.is_file());
    assert_eq!(app.store.index_progress(), Some(0));
    app.ingest();
    assert_eq!(app.store.len(), INDEX_BATCH);
    assert!(app.store.index_progress().is_some());
    assert!(screen(&mut app, 120, 30).contains("indeksleniyor %"));
    while app.ingest() {}
    assert_eq!(app.store.len(), n as usize);
    assert_eq!(app.store.index_progress(), None);
    // Halka tampon sınırı yok; seçim başta kalır.
    assert_eq!(app.store.evicted(), 0);
    assert_eq!(app.selected, Some(0));
    let s = screen(&mut app, 120, 30);
    assert!(s.contains("dosya.pcap") && s.contains("10.0.0.1") && s.contains("UDP"));
    // Yalnızca görünen satırlar ayrıştırıldı.
    assert!(app.store.cached() > 0 && app.store.cached() < 64);
    let e = app.store.get(n as usize - 1).unwrap();
    assert_eq!(e.number, u64::from(n));
    assert!((app.store.rel_time(&e) - f64::from(n - 1) * 0.01).abs() < 1e-6);
    app.apply(Action::NextPanel);
    assert_eq!(app.tree().unwrap().1.len(), 5);
    std::fs::remove_file(path).unwrap();
}

#[test]
fn export_writes_displayed_packets() {
    let mut app = app_with(7, 100);
    assert_eq!(
        app.displayed().collect::<Vec<_>>(),
        (0..7).collect::<Vec<_>>()
    );
    let out = tmp_path("pcapng");
    app.on_key(KeyEvent::new(KeyCode::Char(':'), KeyModifiers::NONE));
    for c in format!("w {}", out.display()).chars() {
        app.on_key(KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE));
    }
    app.on_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
    assert!(app
        .message
        .as_deref()
        .unwrap()
        .starts_with("7 paket yazıldı"));
    assert_eq!(count_packets(&out), 7);

    // Dosya modunda (indeksleme bitmeden bile) tümü yazılır.
    let src = write_file(u32::try_from(INDEX_BATCH).unwrap() + 3, "pcap");
    let mut app = App::from_file(pakiz_storage::IndexedFile::open(&src).unwrap(), "f");
    app.ingest();
    assert_eq!(app.export(out.to_str().unwrap()).unwrap(), INDEX_BATCH + 3);
    assert_eq!(count_packets(&out), INDEX_BATCH + 3);
    app.on_key(KeyEvent::new(KeyCode::Char(':'), KeyModifiers::NONE));
    app.on_key(KeyEvent::new(KeyCode::Char('x'), KeyModifiers::NONE));
    app.on_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
    assert!(app.message.as_deref().unwrap().contains("bilinmeyen"));
    std::fs::remove_file(out).unwrap();
    std::fs::remove_file(src).unwrap();
}

/// `udp_packet` ama hedef port `port`.
fn udp_to(i: u32, port: u16) -> RawPacket {
    let mut p = udp_packet(i);
    p.data[36..38].copy_from_slice(&port.to_be_bytes());
    p
}

fn app_from(packets: Vec<RawPacket>, max: usize) -> App {
    let src = VecSource {
        name: "test0".into(),
        packets: packets.into(),
    };
    App::new(Box::new(src), max)
}

fn key(app: &mut App, code: KeyCode) {
    app.on_key(KeyEvent::new(code, KeyModifiers::NONE));
}

fn type_str(app: &mut App, s: &str) {
    for c in s.chars() {
        key(app, KeyCode::Char(c));
    }
}

fn shown_numbers(app: &App) -> Vec<u64> {
    app.displayed()
        .map(|i| app.store.get(i).unwrap().number)
        .collect()
}

#[test]
fn filter_applies_to_existing_and_new_packets() {
    // Tek numaralı paketler 53'e, çiftler 80'e.
    let pk: Vec<_> = (0..10)
        .map(|i| udp_to(i, if i % 2 == 0 { 80 } else { 53 }))
        .collect();
    let mut app = app_from(pk, 100);
    app.ingest();
    assert_eq!(app.displayed_len(), 10);
    app.set_filter("udp.dstport == 53").unwrap();
    assert_eq!(app.displayed_len(), 0);
    app.ingest();
    assert_eq!(shown_numbers(&app), vec![2, 4, 6, 8, 10]);
    assert_eq!(app.selected, Some(4)); // autoscroll: son eşleşen
                                       // Canlı gelenler eklenirken süzülür.
    let mut app2 = app_from((0..4).map(|i| udp_to(i, 80)).collect(), 100);
    app2.set_filter("udp.dstport == 53 || frame.number == 3")
        .unwrap();
    app2.ingest();
    assert_eq!(shown_numbers(&app2), vec![3]);
    // Geçersiz filtre eskisini korur; boş filtre hepsini gösterir.
    assert!(app.set_filter("udp.dstport ==").is_err());
    assert_eq!(app.filter_text, "udp.dstport == 53");
    app.set_filter("").unwrap();
    app.ingest();
    assert_eq!(app.displayed_len(), 10);
}

#[test]
fn refilter_is_incremental_with_progress() {
    let n = FILTER_BATCH * 2 + 7;
    let pk: Vec<_> = (0..u32::try_from(n).unwrap()).map(udp_packet).collect();
    let mut app = app_from(pk, n);
    while app.ingest() {}
    app.set_filter("udp").unwrap();
    assert_eq!(app.filter_progress(), Some(0));
    app.ingest();
    assert_eq!(app.displayed_len(), FILTER_BATCH);
    assert!(screen(&mut app, 120, 30).contains("filtreleniyor %"));
    while app.ingest() {}
    assert_eq!(app.displayed_len(), n);
    assert_eq!(app.filter_progress(), None);
}

#[test]
fn ring_overflow_keeps_displayed_consistent() {
    // max 4; yalnızca 53'e gidenler (tek indeksli: numara 2,4,6,...) eşleşir.
    let pk: Vec<_> = (0..11)
        .map(|i| udp_to(i, if i % 2 == 0 { 80 } else { 53 }))
        .collect();
    let mut app = app_from(pk, 4);
    app.set_filter("udp.dstport == 53").unwrap();
    app.ingest();
    // Depoda 8..=11 kaldı; gösterilen 8 ve 10.
    assert_eq!(app.store.first_number(), 8);
    assert_eq!(shown_numbers(&app), vec![8, 10]);
    assert!(app.displayed().all(|i| i < app.store.len()));
    assert_eq!(app.selected, Some(1));
    assert_eq!(
        app.store.get(app.selected_index().unwrap()).unwrap().number,
        10
    );
    app.set_filter("udp").unwrap();
    app.ingest();
    assert_eq!(shown_numbers(&app), vec![8, 9, 10, 11]);
}

#[test]
fn ring_overflow_during_refilter() {
    let mut src = VecSource::default();
    for i in 0..6 {
        src.packets.push_back(udp_to(i, 53));
    }
    let mut app = App::new(Box::new(src), 4);
    app.ingest(); // depoda 3..=6
    app.set_filter("udp.dstport == 53").unwrap(); // scan 3'ten başlar
                                                  // Süzme bitmeden 3 yeni paket gelir ve 3,4,5 düşer.
    for i in 6..9 {
        app.add(udp_to(i, 53));
    }
    app.ingest();
    assert_eq!(app.store.first_number(), 6);
    assert_eq!(shown_numbers(&app), vec![6, 7, 8, 9]);
}

#[test]
fn filter_input_validates_and_colors() {
    let mut app = app_with(3, 10);
    let theme = Theme::default();
    let input_bg = |app: &mut App| {
        let mut t = Terminal::new(TestBackend::new(80, 20)).unwrap();
        t.draw(|f| draw(f, app)).unwrap();
        t.backend().buffer()[(3, 18)].bg
    };
    key(&mut app, KeyCode::Char('/'));
    assert_eq!(app.input.as_ref().unwrap().state, FilterState::Empty);
    type_str(&mut app, "ip.ttl ==");
    assert!(matches!(
        app.input.as_ref().unwrap().state,
        FilterState::Invalid(_)
    ));
    assert_eq!(input_bg(&mut app), theme.filter_err_bg);
    assert!(screen(&mut app, 80, 20).contains("hata:"));
    // Enter hatalıyken uygulamaz.
    key(&mut app, KeyCode::Enter);
    assert!(app.input.is_some() && app.filter_text.is_empty());
    type_str(&mut app, " 64");
    assert_eq!(app.input.as_ref().unwrap().state, FilterState::Valid);
    assert_eq!(input_bg(&mut app), theme.filter_ok_bg);
    key(&mut app, KeyCode::Enter);
    assert!(app.input.is_none());
    assert_eq!(app.filter_text, "ip.ttl == 64");
    app.ingest();
    assert_eq!(app.displayed_len(), 3);
    assert!(screen(&mut app, 100, 20).contains("filtre: ip.ttl == 64"));
    // Esc iptal eder; geçmiş ↑ ile gelir.
    key(&mut app, KeyCode::Char('/'));
    for _ in 0..20 {
        key(&mut app, KeyCode::Backspace);
    }
    type_str(&mut app, "tcp");
    key(&mut app, KeyCode::Esc);
    assert_eq!(app.filter_text, "ip.ttl == 64");
    key(&mut app, KeyCode::Char('/'));
    key(&mut app, KeyCode::Up);
    assert_eq!(app.input.as_ref().unwrap().text, "ip.ttl == 64");
    key(&mut app, KeyCode::Down);
    assert_eq!(app.input.as_ref().unwrap().text, "");
    assert_eq!(app.input.as_ref().unwrap().state, FilterState::Empty);
}

#[test]
fn autocomplete_single_common_prefix_and_cycle() {
    let mut app = app_with(1, 10);
    key(&mut app, KeyCode::Char('/'));
    type_str(&mut app, "ip.tt");
    key(&mut app, KeyCode::Tab);
    assert_eq!(app.input.as_ref().unwrap().text, "ip.ttl");
    assert!(app.completion.is_none());
    // Birden çok aday: ortak önek + liste, Tab ile döngü.
    type_str(&mut app, " == 1 && udp.");
    key(&mut app, KeyCode::Tab);
    let c = app.completion.clone().unwrap();
    assert!(c.candidates.len() > 1);
    assert!(c.candidates.iter().all(|n| n.starts_with("udp.")));
    assert_eq!(app.input.as_ref().unwrap().text, "ip.ttl == 1 && udp.");
    assert!(screen(&mut app, 100, 30).contains("aday"));
    key(&mut app, KeyCode::Tab);
    assert_eq!(
        app.input.as_ref().unwrap().text,
        format!("ip.ttl == 1 && {}", c.candidates[0])
    );
    key(&mut app, KeyCode::Tab);
    assert_eq!(
        app.input.as_ref().unwrap().text,
        format!("ip.ttl == 1 && {}", c.candidates[1])
    );
    // Başka tuş döngüyü bitirir.
    key(&mut app, KeyCode::Char(' '));
    assert!(app.completion.is_none());
    // Adaysız kelime değişmez.
    type_str(&mut app, "zzz");
    let before = app.input.as_ref().unwrap().text.clone();
    key(&mut app, KeyCode::Tab);
    assert_eq!(app.input.as_ref().unwrap().text, before);
}

#[test]
fn export_writes_only_filtered() {
    let pk: Vec<_> = (0..6)
        .map(|i| udp_to(i, if i < 2 { 53 } else { 80 }))
        .collect();
    let mut app = app_from(pk, 100);
    app.ingest();
    app.set_filter("udp.dstport == 53").unwrap();
    let out = tmp_path("pcap");
    assert_eq!(app.export(out.to_str().unwrap()).unwrap(), 2);
    assert_eq!(count_packets(&out), 2);
    std::fs::remove_file(&out).unwrap();
    // Dosya modunda: indeksleme/süzme bitmeden de tümü değerlendirilir.
    let src = write_file(u32::try_from(INDEX_BATCH).unwrap() + 3, "pcap");
    let mut app = App::from_file(pakiz_storage::IndexedFile::open(&src).unwrap(), "f");
    app.set_filter("frame.number <= 10").unwrap();
    app.ingest();
    assert_eq!(app.export(out.to_str().unwrap()).unwrap(), 10);
    std::fs::remove_file(out).unwrap();
    std::fs::remove_file(src).unwrap();
}
