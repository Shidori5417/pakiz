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

// ------------------------------------------------------------ Aşama 7/8: akış, görünümler

const SYN: u16 = 0x02;
const ACK: u16 = 0x10;
const PSH: u16 = 0x08;
const RST: u16 = 0x04;
const REQ: &[u8] = b"GET /index.html HTTP/1.1\r\nHost: ornek\r\n\r\n";
const RESP: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";

/// eth + ipv4 + tcp (checksum'lar sıfır). `c` = istemci yönü (10.0.0.1:40000 → 10.0.0.2:80).
fn tcp_pkt(c: bool, seq: u32, ack: u32, flags: u16, payload: &[u8], ts_ms: u64) -> RawPacket {
    let (sip, dip, sp, dp) = if c {
        ([10, 0, 0, 1], [10, 0, 0, 2], 40000u16, 80u16)
    } else {
        ([10, 0, 0, 2], [10, 0, 0, 1], 80, 40000)
    };
    let mut d = vec![0, 1, 2, 3, 4, 5, 0, 1, 2, 3, 4, 6, 0x08, 0x00];
    let total = u16::try_from(40 + payload.len()).unwrap();
    d.extend_from_slice(&[0x45, 0]);
    d.extend_from_slice(&total.to_be_bytes());
    d.extend_from_slice(&[0, 1, 0x40, 0, 64, 6, 0, 0]);
    d.extend_from_slice(&sip);
    d.extend_from_slice(&dip);
    d.extend_from_slice(&sp.to_be_bytes());
    d.extend_from_slice(&dp.to_be_bytes());
    d.extend_from_slice(&seq.to_be_bytes());
    d.extend_from_slice(&ack.to_be_bytes());
    d.extend_from_slice(&((5u16 << 12) | flags).to_be_bytes());
    d.extend_from_slice(&[0xff, 0xff, 0, 0, 0, 0]);
    d.extend_from_slice(payload);
    RawPacket {
        ts: SystemTime::UNIX_EPOCH + Duration::from_millis(ts_ms),
        orig_len: u32::try_from(d.len()).unwrap(),
        data: d,
        ifindex: 1,
    }
}

/// 1-3 el sıkışma, 4 istek, 5 isteğin yeniden iletimi, 6 yanıt, 7 ACK.
fn http_session() -> Vec<RawPacket> {
    let rl = u32::try_from(REQ.len()).unwrap();
    let sl = u32::try_from(RESP.len()).unwrap();
    vec![
        tcp_pkt(true, 100, 0, SYN, b"", 10),
        tcp_pkt(false, 500, 101, SYN | ACK, b"", 20),
        tcp_pkt(true, 101, 501, ACK, b"", 30),
        tcp_pkt(true, 101, 501, ACK | PSH, REQ, 40),
        tcp_pkt(true, 101, 501, ACK | PSH, REQ, 250),
        tcp_pkt(false, 501, 101 + rl, ACK | PSH, RESP, 260),
        tcp_pkt(true, 101 + rl, 501 + sl, ACK, b"", 270),
    ]
}

fn cells(app: &mut App, w: u16, h: u16) -> ratatui::buffer::Buffer {
    let mut t = Terminal::new(TestBackend::new(w, h)).unwrap();
    t.draw(|f| draw(f, app)).unwrap();
    t.backend().buffer().clone()
}

/// `needle` içeren ilk ekran satırında, needle'ın ilk hücresi.
fn cell_of<'a>(
    buf: &'a ratatui::buffer::Buffer,
    needle: &str,
) -> Option<&'a ratatui::buffer::Cell> {
    let area = buf.area;
    for y in 0..area.height {
        let line: String = (0..area.width).map(|x| buf[(x, y)].symbol()).collect();
        if let Some(bx) = line.find(needle) {
            let x = line[..bx].chars().count();
            return Some(&buf[(u16::try_from(x).unwrap(), y)]);
        }
    }
    None
}

#[test]
fn analysis_filter_matches_retransmission() {
    let mut app = app_from(http_session(), 100);
    app.ingest();
    app.set_filter("tcp.analysis.retransmission").unwrap();
    app.ingest();
    assert_eq!(shown_numbers(&app), vec![5]);
    for (f, want) in [
        ("tcp.analysis.flags", vec![5]),
        ("tcp.stream == 0", (1..=7).collect()),
        ("tcp.stream == 1", vec![]),
        ("tcp.seq_rel == 1 && tcp.len > 0", vec![4, 5, 6]),
        ("tcp.ack_rel == 1 && tcp.len > 0", vec![4, 5]),
        (
            "tcp.analysis.duplicate_ack || tcp.analysis.zero_window",
            vec![],
        ),
    ] {
        app.set_filter(f).unwrap();
        app.ingest();
        assert_eq!(shown_numbers(&app), want, "{f}");
    }
    // Otomatik tamamlama sentetik alanları bilir.
    let names: Vec<_> = pakiz_filter::complete("tcp.analysis.re", &app.catalog)
        .iter()
        .map(|d| d.name)
        .collect();
    assert_eq!(names, ["tcp.analysis.retransmission"]);
    assert!(app.catalog.get("udp.stream").is_some());
    // Katman ağacında TCP altında [SEQ/ACK analysis].
    app.set_filter("").unwrap();
    app.ingest();
    app.selected = Some(4);
    let (d, _) = app.tree().unwrap();
    let tcp = d.layers.iter().position(|l| l.protocol == "tcp").unwrap();
    let mut open = HashSet::new();
    open.insert(vec![tcp]);
    let rows = flatten(d, &open);
    let sa = rows
        .iter()
        .find(|r| r.label == "[SEQ/ACK analysis]")
        .unwrap();
    assert_eq!(sa.depth, 1);
    assert!(sa.has_children);
    assert!(rows.iter().any(|r| r.label == "[Stream index: 0]"));
}

#[test]
fn list_marks_analysis_rows_and_process_column() {
    let mut app = app_from(http_session(), 100);
    app.ingest();
    let theme = Theme::default();
    let buf = cells(&mut app, 160, 40);
    let s = screen(&mut app, 160, 40);
    assert!(s.contains("Süreç"), "{s}");
    let c = cell_of(&buf, "[TCP Retransmission]").unwrap();
    assert_eq!((c.fg, c.bg), (theme.bad_tcp_fg, theme.bad_tcp_bg));
    // Süreç sütunu boş (canlı değil) ama satırlar çizilir.
    assert!(app
        .displayed()
        .all(|i| app.store.get(i).unwrap().process.is_none()));
    assert!(s.contains("40000 → 80"));
}

#[test]
fn follow_view_renders_both_directions_with_colors() {
    let mut app = app_from(http_session(), 100);
    app.ingest();
    app.selected = Some(3);
    key(&mut app, KeyCode::Char('F'));
    assert_eq!(app.view, View::Follow);
    let theme = Theme::default();
    let buf = cells(&mut app, 100, 30);
    let s = screen(&mut app, 100, 30);
    assert!(s.contains("Follow TCP Stream (tcp.stream 0)"), "{s}");
    assert!(s.contains("10.0.0.1:40000 ↔ 10.0.0.2:80"));
    // İstek bir kez (yeniden iletim birleştirmede tekrarlanmaz), yanıt sonra.
    assert_eq!(s.matches("GET /index.html HTTP/1.1").count(), 1);
    let req_y = s
        .lines()
        .position(|l| l.contains("GET /index.html"))
        .unwrap();
    let resp_y = s
        .lines()
        .position(|l| l.contains("HTTP/1.1 200 OK"))
        .unwrap();
    assert!(req_y < resp_y);
    assert_eq!(cell_of(&buf, "GET /index").unwrap().fg, theme.follow_client);
    assert_eq!(
        cell_of(&buf, "HTTP/1.1 200").unwrap().fg,
        theme.follow_server
    );
    assert!(s.contains("hello"));
    // Hex ve Raw kipleri.
    key(&mut app, KeyCode::Char('m'));
    let s = screen(&mut app, 100, 30);
    assert!(
        s.contains("kip: Hex") && s.contains("00000000  47 45 54 20"),
        "{s}"
    );
    key(&mut app, KeyCode::Char('m'));
    let s = screen(&mut app, 100, 30);
    assert!(s.contains("kip: Raw") && s.contains("474554202f"));
    key(&mut app, KeyCode::Char('m'));
    // Kaydırma sınırlı; Esc geri döner.
    key(&mut app, KeyCode::Char('G'));
    let total = app.follow.as_ref().unwrap().total;
    assert!(app.follow.as_ref().unwrap().offset < total.max(1));
    key(&mut app, KeyCode::Esc);
    assert_eq!(app.view, View::Packets);
    // Akışsız paket: görünüm açılmaz.
    let mut app = app_from(vec![], 10);
    app.apply(Action::Follow);
    assert_eq!(app.view, View::Packets);
}

#[test]
fn follow_shows_lost_marker_and_scrolls_large_stream() {
    let mut pk = vec![
        tcp_pkt(true, 100, 0, SYN, b"", 10),
        tcp_pkt(false, 500, 101, SYN | ACK, b"", 20),
        tcp_pkt(true, 101, 501, ACK, b"", 30),
        tcp_pkt(true, 101, 501, ACK, b"AAAA", 40),
        // 6 bayt yakalanmadı.
        tcp_pkt(true, 111, 501, ACK, b"BBBB", 50),
        tcp_pkt(true, 115, 501, RST, b"", 60),
    ];
    // Ayrı büyük akış: 300 satır.
    let mut seq = 1000u32;
    let line = b"satir-satir-satir\n";
    pk.push(tcp_pkt(false, 999, 0, SYN, b"", 70));
    for i in 0..300 {
        pk.push(tcp_pkt(false, seq, 0, ACK, line, 80 + i));
        seq += u32::try_from(line.len()).unwrap();
    }
    let mut app = app_from(pk, 1000);
    while app.ingest() {}
    app.selected = Some(4);
    app.apply(Action::Follow);
    let s = screen(&mut app, 100, 30);
    assert!(
        s.contains("AAAA") && s.contains("[6 bayt eksik]") && s.contains("BBBB"),
        "{s}"
    );
    assert!(s.contains("durum: RST"));
    // RST satırı kırmızı.
    app.apply(Action::Back);
    let theme = Theme::default();
    assert_eq!(
        app.store.flow(5).unwrap().flags,
        pakiz_flow::AnalysisFlags::RST
    );
    let buf = cells(&mut app, 160, 40);
    let c = cell_of(&buf, "40000 → 80 [RST]").unwrap();
    assert_eq!((c.fg, c.bg), (theme.rst_fg, theme.rst_bg));
    // Kayıp segment sonrası paket: "Previous segment not captured" (kötü TCP).
    let c = cell_of(&buf, "[TCP Previous segment not captured]").unwrap();
    assert_eq!(c.fg, theme.bad_tcp_fg); // seçili satır: zemin seçim rengi
                                        // Büyük akış: yalnızca görünen satırlar; G sona gider.
    app.selected = Some(7);
    app.apply(Action::Follow);
    let s = screen(&mut app, 100, 30);
    assert!(s.contains("[1-") && s.contains("/300]"), "{s}");
    app.apply(Action::Bottom);
    let s = screen(&mut app, 100, 30);
    assert!(s.contains("/300/300]") || s.contains("-300/300]"), "{s}");
}

#[test]
fn conversations_table_sort_and_filter() {
    let mut pk = http_session();
    pk.push(udp_packet(9));
    pk.push(udp_packet(10));
    let mut app = app_from(pk, 100);
    app.ingest();
    key(&mut app, KeyCode::Char('c'));
    assert_eq!(app.view, View::Conversations);
    let s = screen(&mut app, 140, 20);
    assert!(s.contains("Konuşmalar (2)"), "{s}");
    assert!(s.contains("10.0.0.1:40000") && s.contains("10.0.0.2:80"));
    assert!(s.contains("10.0.0.1:1234") && s.contains("10.0.0.2:53"));
    assert!(s.contains("TCP") && s.contains("UDP") && s.contains("Kurulu"));
    assert_eq!(app.conv.rows[0].stream.proto, pakiz_flow::Proto::Tcp);
    // s: paket sayısına göre (TCP 7 > UDP 2) → bayta göre → süre.
    key(&mut app, KeyCode::Char('s'));
    assert_eq!(app.conv.sort, ConvSort::Packets);
    assert!(screen(&mut app, 140, 20).contains("Pkt A→B▼"));
    assert_eq!(app.conv.rows[0].packets, [5, 2]);
    // j + Enter: UDP akışını süz.
    key(&mut app, KeyCode::Char('j'));
    key(&mut app, KeyCode::Enter);
    assert_eq!(app.view, View::Packets);
    assert_eq!(app.filter_text, "udp.stream == 0");
    app.ingest();
    assert_eq!(shown_numbers(&app), vec![8, 9]);
    // :conv komutu da açar.
    key(&mut app, KeyCode::Char(':'));
    type_str(&mut app, "conv");
    key(&mut app, KeyCode::Enter);
    assert_eq!(app.view, View::Conversations);
    key(&mut app, KeyCode::Char('q'));
    assert_eq!(app.view, View::Packets);
    assert!(!app.quit);
}

#[test]
fn stats_view_renders_tabs_and_names() {
    let mut pk = http_session();
    pk.push(udp_packet(9));
    let mut app = app_from(pk, 100);
    app.ingest();
    app.analyzer
        .dns
        .insert("10.0.0.2".parse().unwrap(), "sunucu.ornek");
    key(&mut app, KeyCode::Char('S'));
    assert_eq!(app.view, View::Stats);
    let s = screen(&mut app, 140, 30);
    assert!(s.contains("Paket/sn") && s.contains("Bayt/sn"), "{s}");
    assert!(s.contains("Protokol hiyerarşisi") && s.contains("Top talkers"));
    assert!(s.contains("toplam 8 paket"));
    let hier: Vec<&str> = s
        .lines()
        .filter(|l| l.contains("tcp") || l.contains("udp"))
        .collect();
    assert!(hier.iter().any(|l| l.contains("87.5%")), "{hier:?}"); // 7/8 tcp
    key(&mut app, KeyCode::Tab);
    assert_eq!(app.stats_view.tab, StatsTab::Talkers);
    let s = screen(&mut app, 140, 30);
    assert!(s.contains("sunucu.ornek") && s.contains("10.0.0.1"), "{s}");
    key(&mut app, KeyCode::Char('3'));
    let s = screen(&mut app, 140, 30);
    assert!(s.contains("IP konuşmaları") && s.contains("10.0.0.2"));
    key(&mut app, KeyCode::Char('n'));
    assert!(screen(&mut app, 140, 30).contains("sunucu.ornek"));
    key(&mut app, KeyCode::Char('4'));
    let s = screen(&mut app, 140, 30);
    assert!(s.contains("Hedef port") && s.contains("80") && s.contains("53"));
    // Ad çözümleme paket listesinde de etkili.
    key(&mut app, KeyCode::Esc);
    let s = screen(&mut app, 160, 40);
    assert!(
        s.contains("sunucu.ornek") && s.contains("ad çözümleme"),
        "{s}"
    );
    key(&mut app, KeyCode::Char('n'));
    assert!(!screen(&mut app, 160, 40).contains("sunucu.ornek"));
    // Yardım yeni tuşları listeler.
    key(&mut app, KeyCode::Char('?'));
    let s = screen(&mut app, 100, 40);
    assert!(s.contains("Follow") && s.contains("konuşmalar") && s.contains("ad çözümleme"));
}

#[test]
fn file_mode_analyzes_during_indexing() {
    let p = tmp_path("pcap");
    let mut w = pakiz_storage::create(&p, pakiz_storage::Format::from_path(&p)).unwrap();
    for pk in http_session() {
        w.write_packet(&pk).unwrap();
    }
    w.flush().unwrap();
    let mut app = App::from_file(pakiz_storage::IndexedFile::open(&p).unwrap(), "f");
    app.set_filter("tcp.analysis.retransmission").unwrap();
    while app.ingest() {}
    assert_eq!(app.store.analyzed(), 7);
    assert_eq!(shown_numbers(&app), vec![5]);
    assert_eq!(app.analyzer.stats.total().packets, 7);
    // Yeniden süzme saklanan özeti kullanır.
    app.set_filter("tcp.stream == 0 && tcp.len > 0").unwrap();
    while app.ingest() {}
    assert_eq!(shown_numbers(&app), vec![4, 5, 6]);
    let e = app.store.get(4).unwrap();
    assert!(e.flow.unwrap().flags.has_warning());
    app.selected = Some(0);
    app.apply(Action::Follow);
    let s = screen(&mut app, 100, 30);
    assert!(
        s.contains("GET /index.html") && s.contains("HTTP/1.1 200 OK"),
        "{s}"
    );
    std::fs::remove_file(p).unwrap();
}
