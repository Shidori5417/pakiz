# pakiz — mimari

Terminalde çalışan, Linux'a özel, Wireshark benzeri paket analiz aracı. Binary adı: `pakiz`.

## Crate'ler (Cargo workspace, `crates/<ad>`, paket adı `pakiz-<ad>`)

| crate    | sorumluluk | bağımlılık |
|----------|------------|------------|
| dissect  | `RawPacket` (ts, data, orig_len, ifindex), `Dissector` trait'i, `Registry`, alan ağacı (`Field{name,value,offset,len,children,malformed}`), tüm protokoller. Saf, unsafe yok. | — |
| capture  | AF_PACKET raw socket, TPACKET_V3 mmap ring (yoksa recv), arayüz listeleme, promisc, SO_ATTACH_FILTER (klasik BPF), PACKET_STATISTICS, yetki hatası + `setcap` önerisi. **unsafe yalnızca burada**, her blok `// SAFETY:` yorumlu. Yakalama kendi OS thread'inde, `crossbeam-channel` ile `RawPacket` gönderir. | dissect |
| storage  | pcap + pcapng okuma/yazma, büyük dosya için ofset indeksi (paketi gerektiğinde oku). | dissect |
| filter   | display filter: elle lexer, Pratt parser, AST, paket başı değerlendirici; alan adları registry'den. Klasik BPF derleyicisi (`-f` yakalama filtresi için basit ifadeler) de burada. | dissect |
| flow     | TCP 5-tuple akış takibi, sıra no ile yeniden birleştirme, retransmission/dup-ack/zero-window/RST analizi, UDP conversation. | dissect |
| stats    | pps/bps zaman serisi, protokol dağılımı, top talker, conversation/port tabloları, süreç eşleme (sock_diag netlink → /proc fallback), DNS ad önbelleği. | dissect |
| tui      | ratatui + crossterm: 3 panel, ek görünümler, vim tuşları, fare, tema, sanal kaydırma, ~30 fps, halka tampon. | hepsi |
| bin      | `pakiz` binary: clap CLI, config (`~/.config/pakiz/config.toml`), tokio runtime, `--no-tui` satır çıktısı, anyhow. | hepsi |

## Veri akışı

```
capture thread ──RawPacket──▶ crossbeam channel ──▶ app (tokio)
                                                    ├─ dissect::Registry → PacketSummary + Field ağacı (lazily)
                                                    ├─ flow / stats güncelle
                                                    ├─ filter değerlendir
                                                    └─ tui (30 fps tick) / --no-tui stdout
```

## Kurallar
- Kütüphane crate'lerinde `thiserror`, binary'de `anyhow`. Üretim kodunda `unwrap`/`expect` yok (testlerde serbest).
- Dissect zero-copy (`&[u8]`), asla panic yok; sınır dışı okuma → alan `malformed`.
- `cargo clippy --workspace --all-targets -- -W clippy::pedantic -D warnings` ve `cargo fmt --check` temiz.
- Workspace düzeyinde `[workspace.lints]`; `unsafe_code = "forbid"` capture hariç tüm crate'lerde.
