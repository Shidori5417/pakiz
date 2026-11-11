# pakiz: mimari

Terminalde çalışan, Linux'a özel, Wireshark benzeri paket analiz aracı. Binary adı
`pakiz`. Cargo workspace yapısındadır: `crates/<ad>` dizinleri, paket adları
`pakiz-<ad>`.

## Crate'ler ve bağımlılıklar

```
                 ┌──────────────────────── bin (pakiz) ─────────────────────────┐
                 │ clap CLI, config.rs (serde+toml), tokio, anyhow              │
                 └──┬─────────┬──────────┬──────────┬─────────┬─────────┬───────┘
                    │         │          │          │         │         │
                    ▼         │          ▼          │         ▼         ▼
                  tui ────────┼──────▶ filter       │       capture   storage
                  │ │ │ │     │          │          │         │         │
                  │ │ │ └─────┼──────────┼───▶ storage        │         │
                  │ │ └───────┼──▶ stats │          │         │         │
                  │ └─────────┼──▶ flow  │          │         │         │
                  ▼           ▼    │     ▼          ▼         ▼         ▼
                 ──────────────────┴── dissect (bağımlılığı yok) ─────────────
```

| crate | sorumluluk | pakiz bağımlılıkları |
|---|---|---|
| `dissect` | `RawPacket`, `Dissector` trait'i, `Registry` (kayıt sırası = öncelik), `Layer`/`Field` ağacı, `FieldDef` kataloğu, tüm protokoller (`src/proto/*.rs`). Saf; `unsafe` yok, panic yok, sınır dışı okuma `malformed` alan olur. | — |
| `capture` | `AF_PACKET` soketi, `TPACKET_V3` mmap halkası (olmazsa `recvfrom`), arayüz listeleme (`getifaddrs`), promisc, `SO_ATTACH_FILTER`, `PACKET_STATISTICS`, yetki hatası ve `setcap` önerisi. Workspace'te `unsafe` olan **tek** crate; her blok `// SAFETY:` yorumlu (`clippy::undocumented_unsafe_blocks = deny`). Block ayrıştırma saf `parse_block(&[u8], …)` fonksiyonudur (root'suz test edilir). | dissect |
| `storage` | pcap ve pcapng okuma/yazma (elle), `IndexedFile`: büyük dosyalar için ofset indeksi, paket gerektiğinde diskten okunur. | dissect |
| `filter` | Display filter: elle lexer, Pratt parser, AST, alan kataloğuna karşı derleme, paket başı değerlendirme, öneri (OSA mesafesi), otomatik tamamlama. `bpf`: tcpdump alt kümesi → klasik BPF derleyici ve yorumlayıcısı (testler için). | dissect |
| `flow` | 5-tuple akış tablosu, TCP yeniden birleştirme, analiz (retransmission, dup ACK, out-of-order, zero window, kayıp segment, keep-alive, RST), UDP konuşmaları, Follow Stream verisi, sentetik `tcp.stream`/`tcp.analysis.*` alanları (`annotate`). | dissect |
| `stats` | pps/bps zaman serisi, protokol hiyerarşisi, top talker, konuşma ve port tabloları, `ProcessResolver` (sock_diag netlink, olmazsa `/proc/net` + `/proc/*/fd`), `DnsCache`. | dissect |
| `tui` | ratatui + crossterm. `App` (durum + eylemler, render'dan bağımsız), `ui`/`views` (çizim), `Keymap` (tuş → `Action`, metinden tuş çözme), `Theme` (dark/light) + `ColorRule` (display filter ile renklendirme), `PacketStore` (halka tampon / dosya indeksi), ortak işleme hattı `Analyzer`. | dissect, filter, flow, stats, storage |
| `bin` | `pakiz` binary: CLI, config dosyası (`config.rs`), mod seçimi (TUI / `--no-tui` / `--count` / `--stats` / dönüştürme), yazıcı thread'i, sinyaller. | hepsi |

Fuzz hedefleri workspace dışındadır (`exclude`): `crates/dissect/fuzz`
(`dissect_frame`) ve `crates/filter/fuzz` (`filter_parse`: display + BPF filtresi
derle, derlenen filtreyi girdiden kurulan bir pakette çalıştır, tamamlama).

## Threading

```
 [pakiz-capture thread]            [pakiz-writer thread, yalnız -w ile TUI]      [ana thread]
  TPACKET_V3 block döngüsü ─┐
  (poll 100 ms, stop flag)  │ bounded(65 536) crossbeam
  veya recvfrom döngüsü ────┴──────▶ dosyaya yaz ──bounded(65 536)──▶ TUI olay döngüsü
                                     (UI kanalı doluysa UI için düşür,   veya tokio current_thread
                                      dosyaya yine yaz)                   döngüsü (--no-tui/--count)
```

- **Yakalama** kendi OS thread'inde çalışır (`start_capture`). Kanal doluysa paket
  düşer ve `app_dropped` sayacı artar. `CaptureHandle::stop`/`Drop` bayrağı kaldırır,
  thread'i bekler ve promisc'i kapatır.
- **TUI** ana thread'de senkron bir döngüdür (`Tui::run`): kaynaktan en fazla
  `DRAIN_BATCH` paket çeker, olayları işler, en fazla `general.fps` (varsayılan 30)
  ile çizer. SIGTERM/SIGHUP bir bayrakla döngüyü bitirir, `Drop` terminali geri
  yükler. Panic hook da terminali geri yükler.
- **`--no-tui` / `--count`**: `tokio` `current_thread` runtime'ında `select!` ile
  Ctrl-C, SIGTERM ve periyodik tick (20 ms / 1 s) beklenir.
- Dosya modunda (`-r`) yakalama thread'i yoktur. İndeksleme, analiz ve filtreleme
  her tick'te artımlı ilerler (`INDEX_BATCH`, `ANALYZE_BATCH`, `FILTER_BATCH`), böylece
  arayüz büyük dosyada da yanıt verir.

## Veri akışı ve Analyzer hattı

```
RawPacket ─▶ Analyzer::analyze(number, raw)
              1. Registry::dissect_numbered     → Dissection (katmanlar + Summary)
              2. FlowTable::process             → PacketAnalysis → FlowTag (stream, yön, bayraklar, göreli seq/ack)
              3. Stats::record_packet           (kümülatif)
              4. DnsCache::record               (A/AAAA cevapları → ad)
              5. ProcessResolver (yalnız canlı) → süreç adı (akış başına önbellek)
              6. annotate(dissection, FlowTag)  → sentetik tcp.stream / tcp.analysis.* alanları
            ─▶ Analyzed { dissection, flow, process }
              ├─ TUI:   PacketStore'a Entry (ham veri + Summary + FlowTag + süreç), filtre → gösterilenler
              └─ satır: filtre eşleşirse yaz, -w ile dosyaya
```

`Analyzer` TUI ve `--no-tui` için ortaktır. Akış analizi durumlu olduğundan her
paket hattan **bir kez** geçer. Paket başına yalnızca küçük `FlowTag` saklanır.
Sonradan yeniden ayrıştırmada (filtre değişimi, katman ağacı, renklendirme)
`Analyzer::dissect(raw, number, flow)` aynı sentetik alanları tekrar ekler. Akış,
istatistik ve DNS durumu kümülatiftir; halka tampondan düşen paketlerden
etkilenmez.

**Display filter**: `Filter::compile(src, &catalog())` derler. Katalog registry
alanları ve `pakiz_flow::FIELDS` toplamıdır. Filtre değişince `App` paketleri
`FILTER_BATCH`'lik dilimlerle yeniden değerlendirir. Gösterilen paket numaraları
`shown` kuyruğunda tutulur.

**Renklendirme**: `App::coloring` = config'teki `[[coloring]]` kuralları +
temanın varsayılan kuralları (`Theme::default_coloring`). Her kural derlenmiş bir
display filter ve isteğe bağlı fg/bg değerinden oluşur. Liste çizilirken
yalnızca **görünür** satırlar yeniden ayrıştırılır ve ilk eşleşen kural uygulanır.
Malformed paketler her zaman `malformed` rengini alır.

**Yakalama filtresi**: `bpf::compile` → `Vec<SockFilter>` → `libc::sock_filter`
(bin'deki `to_sock_filter`) → `SO_ATTACH_FILTER`. Yan yana iki ilkel örtük `and`
sayılır (`udp port 53`).

## Config

`bin/src/config.rs` önce `$XDG_CONFIG_HOME/pakiz/config.toml`, sonra
`~/.config/pakiz/config.toml` yolunu dener (`--config` ile değiştirilebilir;
açıkça verilen dosya bulunamazsa hata verir). Değerler `toml::Spanned` ile
okunur. Böylece TOML sözdizimi hatası ve anlamsal hatalar (bilinmeyen tema, renk,
eylem, tuş, tuş çakışması, renklendirme filtresi) `dosya:satır:sütun` biçiminde,
kaynak satırı ve `^` işaretiyle raporlanır. Bilinmeyen alanlar reddedilir
(`deny_unknown_fields`). Öncelik sırası: CLI bayrağı > config > varsayılan.
`--dump-config` çıktısı `docs/config.example.toml` ile birebir aynıdır (testle
korunur) ve tekrar okunduğunda varsayılanları verir.

## Kurallar

- Kütüphane crate'lerinde `thiserror`, binary'de `anyhow`. Üretim kodunda
  `unwrap`/`expect` yoktur (workspace lint'i `unwrap_used`/`expect_used`; testlerde
  `cfg_attr(test, allow)`).
- Dissect zero-copy (`&[u8]`) çalışır ve asla panic etmez. Her dissector'ın
  truncation sweep testi vardır.
- `[workspace.lints]`: `unsafe_code = "forbid"`. Yalnızca `capture` bunu `allow`
  ile ezer; orada `unsafe_op_in_unsafe_fn = deny` ve
  `clippy::undocumented_unsafe_blocks = deny` geçerlidir.
- CI (`.github/workflows/ci.yml`): `fmt --check`, `clippy --workspace --all-targets
  -- -W clippy::pedantic -D warnings`, `test --workspace`, `bench --no-run`. Ayrı
  bir job'da nightly + cargo-fuzz ile her hedef 60 sn çalışır.
