# pakiz

Linux için terminalde çalışan, Wireshark benzeri paket analizörü. libpcap
kullanmaz: yakalama doğrudan `AF_PACKET` soketi ve `TPACKET_V3` mmap halkasıyla
yapılır. Arayüz ratatui ile çizilir.

## Özellikler

- **Canlı yakalama**: `AF_PACKET` + `TPACKET_V3` mmap halkası (kullanılamazsa
  `recvfrom`), promiscuous mod, kernel düşen paket sayaçları, klasik BPF yakalama
  filtresi (`-f`, kernel'e `SO_ATTACH_FILTER` ile bağlanır).
- **Dosya**: pcap ve pcapng okuma/yazma. Büyük dosyalar indekslenir, paketler
  gerektiğinde diskten okunur.
- **Protokoller**: Ethernet, 802.1Q VLAN, ARP, IPv4, IPv6, ICMP, ICMPv6, TCP, UDP,
  DNS (UDP/TCP), mDNS, DHCP, NTP, HTTP/1.x, TLS (el sıkışma, SNI), QUIC (başlık ve
  Initial), SSH (sürüm, KEXINIT), MQTT.
- **Display filter** (`-Y`, TUI'de `/`): Wireshark sözdizimi, alan adları
  registry'den gelir, yazarken doğrulanır ve Tab ile tamamlanır.
- **Akış analizi**: TCP yeniden birleştirme, retransmission, dup ACK, out-of-order,
  zero window, kayıp segment işaretleri (`tcp.analysis.*`), `tcp.stream` /
  `udp.stream`, Follow Stream (ASCII / Hex / Raw).
- **İstatistik**: pps/bps grafiği, protokol hiyerarşisi, top talkers,
  konuşma ve port tabloları, DNS cevaplarından ad çözümleme, canlıda paketin yerel
  sürecini bulma (sock_diag, olmazsa `/proc`).
- **TUI**: üç panel (liste / katman ağacı / hex), vim tuşları, fare, sanal kaydırma,
  halka tampon, tema, config'ten değiştirilebilen tuşlar ve renklendirme kuralları.
- **TUI'siz kullanım**: `--no-tui` her paketi tek satır yazar, `--count` sayaç
  modudur, `--stats` sonda özet basar. `-r a.pcap -Y ... -w b.pcapng` ile süzerek
  dönüştürme yapılabilir.

## Kurulum

**Seçenek A (önerilen): `cargo install`.** Binary `~/.cargo/bin/pakiz` olur ve
dizinden bağımsız çalışır.

```sh
cargo install --path crates/bin
# Canlı yakalama için root yerine yetenek (capability) ver:
sudo setcap cap_net_raw,cap_net_admin=eip "$(command -v pakiz)"   # bash/zsh
sudo setcap cap_net_raw,cap_net_admin=eip (command -v pakiz)      # fish
pakiz -i enp6s0
```

**Seçenek B: yerel derleme.** Komutlar proje kökünde çalıştırılmalıdır
(`target/release/...` göreli bir yoldur); başka dizinden mutlak yol kullanın.

```sh
cd /proje/kökü
cargo build --release
sudo setcap cap_net_raw,cap_net_admin=eip target/release/pakiz
./target/release/pakiz -i enp6s0
```

Not: Dosya değişince capability silinir; her yeniden derleme/kurulumdan sonra
`setcap` komutunu tekrar verin.

Rust stable (2021 edition) ile derlenir. Çalışma zamanında libpcap gerekmez.
`cap_net_raw` soket açmak için, `cap_net_admin` promiscuous mod için gereklidir.
Yetki yoksa program hangi komutu çalıştırmanız gerektiğini söyler.

## Kullanım

```sh
pakiz                                   # arayüz seçtirir, canlı TUI
pakiz -i eth0                           # eth0'da canlı TUI
pakiz -i eth0 -f 'udp port 53'          # kernel'de yalnız DNS yakala
pakiz -i eth0 -Y 'tcp.port == 443'      # TUI'yi bir filtreyle başlat
pakiz -i wlan0 -w out.pcapng            # TUI + dosyaya yaz
pakiz -r yakalama.pcap                  # dosyayı TUI'de aç
pakiz -r yakalama.pcap --no-tui -Y dns  # satır çıktısı, yalnız DNS
pakiz -r a.pcap -Y http -w b.pcapng     # süz ve pcapng'ye dönüştür
pakiz -r a.pcap --stats                 # protokol dağılımı + top talkers
pakiz -i eth0 --count                   # saniyede bir paket/bayt/düşen sayacı
pakiz --list-interfaces
pakiz --theme light                     # açık tema
pakiz --dump-config > ~/.config/pakiz/config.toml
```

| Bayrak | Açıklama |
|---|---|
| `-i, --interface <ARAYÜZ>` | Yakalanacak arayüz (yoksa `general.default_interface`, o da yoksa seçim ekranı) |
| `-r, --read <DOSYA>` | pcap/pcapng dosyasından oku |
| `-w, --write <DOSYA>` | Dosyaya yaz (`.pcapng` uzantısı → pcapng, diğerleri pcap) |
| `-f, --capture-filter <FİLTRE>` | Kernel BPF yakalama filtresi |
| `-Y, --display-filter <FİLTRE>` | Display filter |
| `--no-tui` | TUI yerine satır çıktısı |
| `--count` | Ham sayaç modu |
| `--stats` | Sonda özet istatistik |
| `-n, --resolve` | DNS'ten öğrenilen adları göster |
| `--max-packets <N>` | Bellekte tutulacak en fazla paket |
| `--theme <AD>` | `dark` veya `light` |
| `--config <YOL>` | Başka bir config dosyası |
| `--dump-config` | Varsayılan config'i yaz ve çık |
| `--no-promisc`, `--force-recv` | Promiscuous modu kapat / mmap yerine `recvfrom` |

Komut satırı bayrakları config dosyasındaki değerleri ezer.

## Tuşlar (varsayılan)

| Tuş | Eylem (`[keys]` adı) |
|---|---|
| `j` / `↓`, `k` / `↑` | aşağı / yukarı (`down`, `up`) |
| `g` / `Home`, `G` / `End` | başa / sona (`top`, `bottom`) |
| `Ctrl-d` / `PageDown`, `Ctrl-u` / `PageUp` | yarım sayfa (`half_page_down`, `half_page_up`) |
| `Tab` | panel odağı (`next_panel`) |
| `Enter` / `Space` | ağaçta aç/kapa (`toggle`) |
| `h` / `←`, `l` / `→` | kapa / aç (`collapse`, `expand`) |
| `/` | display filter (Tab tamamlar, ↑/↓ geçmiş) (`filter`) |
| `:` | komut: `:q`, `:w dosya`, `:follow`, `:conv`, `:stats` (`command`) |
| `p` | duraklat / devam (`pause`) |
| `a` | otomatik kaydırma (`autoscroll`) |
| `F` | seçili akışı izle, Follow Stream (`follow`) |
| `c` | konuşmalar (`conversations`) |
| `S` | istatistikler (`statistics`) |
| `n` | DNS ad çözümleme aç/kapa (`toggle_resolve`) |
| `m` | Follow: ASCII / Hex / Raw (`cycle_mode`) |
| `s` | Konuşmalar: sıralama sütunu (`sort`) |
| `1`-`4` | İstatistik alt sekmesi (`tab1`..`tab4`) |
| `Esc` | görünümden geri (`back`) |
| `?` | yardım (`help`) |
| `q` / `Ctrl-c` | çıkış; ek görünümdeyken geri (`quit`) |
| fare | tıklayınca seçer, tekerlekle kaydırır |

## Filtre dili

Display filter (`-Y`, `/`, `[[coloring]]`):

```text
tcp                                   # alan/protokol varlığı
ip.addr == 10.0.0.1
ip.src == 192.168.0.0/16 and not tcp.port == 22
tcp.port == 80 or tcp.port == 443
tcp.flags.syn == 1 && tcp.flags.ack == 0
dns.qry.name contains "example"
http.request.method == "GET"
tls.handshake.extensions_server_name matches "goog"
eth.addr == aa:bb:cc:dd:ee:ff
tcp.analysis.flags                    # herhangi bir TCP uzman uyarısı
tcp.stream == 3
frame.len > 1000
```

Karşılaştırmalar: `== != > < >= <=` (ve `eq ne gt lt ge le`), `contains`,
`matches` / `~` (regex). Değerler: sayı (`10`, `0x1f`), `"metin"`, IPv4/IPv6
(ağ önekiyle), MAC, `true` / `false`. Mantık: `and` / `&&`, `or` / `||`,
`not` / `!`, parantez. `in {...}` kümesi ve alan dilimleme (`[0:2]`) yoktur. Hatalar sütun işaretiyle gösterilir; bilinmeyen alan adı
için en yakın ad önerilir.

Yakalama filtresi (`-f`, tcpdump alt kümesi, kernel'de klasik BPF):

```text
tcp | udp | icmp | arp | ip | ip6
[src|dst] host 1.2.3.4
[src|dst] port 53
udp port 53                     # yan yana ilkel = örtük and
tcp port 80 and not host 10.0.0.1
(tcp port 80 or tcp port 443) and src host 192.168.1.2
```

## Yapılandırma

Konum: `$XDG_CONFIG_HOME/pakiz/config.toml`, yoksa `~/.config/pakiz/config.toml`.
Dosya yoksa varsayılanlar kullanılır. Hatalı config'te program `dosya:satır:sütun`
ile hatayı gösterip çıkar. Tüm seçenekleri içeren yorumlu örnek:
[`docs/config.example.toml`](docs/config.example.toml) (`pakiz --dump-config` ile
aynıdır).

```toml
[general]
default_interface = "wlan0"
max_packets = 200000
fps = 30
resolve_names = true
autoscroll = true

[theme]
name = "light"          # dark | light
selection = "#c8d8f0"   # bg, fg, selection, highlight, status, border, border_focus

[theme.protocols]
tcp = "#c8a2ff"         # tcp udp arp icmp dns http malformed other

[keys]
down = ["j", "Down"]    # bir eylemin tüm tuşlarını değiştirir
filter = ["/", "Ctrl-f"]
quit = ["q", "Ctrl-c"]

# Sırayla denenir, ilk eşleşen kazanır; temanın varsayılan kurallarından önce gelir.
[[coloring]]
filter = "tcp.port == 22"
fg = "black"
bg = "#a0d0ff"

[[coloring]]
filter = "dns.flags.rcode != 0"
fg = "red"
```

Tuş yazımı: `j`, `G`, `?`, `Ctrl-d`, `Alt-x`, `Shift-Tab`, `Enter`, `Esc`, `Tab`,
`Space`, `Up`/`Down`/`Left`/`Right`, `Home`, `End`, `PageUp`, `PageDown`,
`Backspace`, `Delete`, `Insert`, `F1`..`F24`. Aynı tuşu config'te iki eyleme
vermek hatadır. Config'teki bir tuş başka bir eylemin *varsayılan* tuşuysa o
eylemden alınır.

Varsayılan renklendirme kuralları (sırayla): kötü TCP (retransmission, dup ACK,
out-of-order, kayıp segment, keep-alive: siyah zemin, kırmızı yazı), sıfır/dolu
pencere, RST, ARP, ICMP/ICMPv6, DNS/mDNS, HTTP/TLS, TCP, UDP. Bu kurallar temanın
protokol renklerini kullanır. Bozuk (malformed) paketler her zaman `malformed`
rengiyle gösterilir.

## Sınırlamalar

- **Şifreli trafik çözülmez**: TLS ve QUIC yükleri deşifre edilmez (anahtar
  günlüğü desteği yoktur). QUIC'te yalnızca açık başlık alanları gösterilir.
- **IP parça birleştirme yok**: IPv4/IPv6 fragment'lar birleştirilmez. Parçalı
  paketlerde üst katman ayrıştırılmaz.
- **TCP birleştirme** Follow Stream ve analiz içindir. HTTP gibi birden çok
  segmente yayılan mesajlar paket listesinde tek PDU olarak birleştirilmez.
- **BPF bir alt kümedir**: yalnızca yukarıdaki ilkeller desteklenir. `host`/`port`
  yalnızca IPv4 içindir, VLAN etiketli çerçeveler eşleşmez, `net`, `portrange`,
  `len`, bayt indeksleme (`tcp[13]`) ve `vlan` yoktur.
- **Süreç eşleme best-effort'tur**: kısa ömürlü bağlantılar, başka ağ ad
  alanları ve konteynerler için süreç bulunamayabilir. Yetki gerekebilir.
- **Ad çözümleme** yalnızca yakalanan DNS cevaplarına dayanır. Ters DNS sorgusu
  yapılmaz.
- **Yalnızca Linux** (`AF_PACKET`) ve yalnızca Ethernet / loopback / cooked olmayan
  bağlantı katmanı. Wi-Fi monitor mode (radiotap) ayrıştırılmaz.
- Dissector'lar port ve içerik sezgisine dayanır. Standart dışı portlardaki
  protokoller tanınmayabilir; "decode as" yoktur.
- Yardım penceresi (`?`) varsayılan tuşları gösterir, config'teki atamaları
  yansıtmaz.
- `--help` Türkçedir ama clap'in kendi hata mesajları (ör. bilinmeyen bayrak)
  İngilizce kalır.

## Geliştirme

```sh
cargo test --workspace
cargo clippy --workspace --all-targets -- -W clippy::pedantic -D warnings
cargo fmt --check
cargo bench --workspace --no-run
cd crates/dissect && cargo +nightly fuzz run dissect_frame
cd crates/filter  && cargo +nightly fuzz run filter_parse
```

Mimari için [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md), yeni protokol eklemek
için [`docs/NEW_DISSECTOR.md`](docs/NEW_DISSECTOR.md) dosyasına bakın.
