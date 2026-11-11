# Yeni dissector nasıl eklenir

Örnek olarak UDP 7 üzerinde çalışan, uydurma bir "ECHO" protokolü ekleyeceğiz.
Protokolün başlığında 2 bayt `id`, 1 bayt `kind` vardır, ardından yük gelir.
Gerçek bir örnek için `crates/dissect/src/proto/ntp.rs` dosyasına bakabilirsiniz.

## 1. Protokol dosyası: `crates/dissect/src/proto/echo.rs`

```rust
//! ECHO (UDP 7): örnek protokol.

use super::util::udp_port;
use crate::{
    Ctx, DissectResult, Dissector, Field, FieldDef, FieldType as T, FieldValue as V, Layer,
    NextHint, Reader,
};

pub struct Echo;

/// Filtre ve otomatik tamamlama bu listeden beslenir. İlk girdi protokolün kendisidir.
const FIELDS: &[FieldDef] = &[
    FieldDef::new("echo", T::None, "Echo Protocol"),
    FieldDef::new("echo.id", T::U16, "Identifier"),
    FieldDef::new("echo.kind", T::U8, "Kind"),
    FieldDef::new("echo.payload", T::Bytes, "Payload"),
];

impl Dissector for Echo {
    fn name(&self) -> &'static str {
        "echo" // filtre adı
    }
    fn display_name(&self) -> &'static str {
        "ECHO" // paket listesindeki Protocol sütunu
    }
    /// Ucuz olmalı: alt katmanın ipucuna (port, EtherType, IP proto) ve gerekirse ilk baytlara bakar.
    fn can_dissect(&self, _: &Ctx, hint: &NextHint, data: &[u8]) -> bool {
        udp_port(hint, &[7]) && !data.is_empty()
    }
    fn fields(&self) -> &'static [FieldDef] {
        FIELDS
    }

    /// `data`: bu katmandan itibaren kalan baytlar; `base`: frame içindeki mutlak ofset.
    /// Asla panic etmemeli: tüm okumalar `Reader` üzerinden `Option` döner.
    fn dissect(&self, ctx: &mut Ctx, data: &[u8], base: usize) -> DissectResult {
        let r = Reader::new(data, base);
        let mut l = Layer::new("echo", "Echo Protocol", base, data.len());
        let id = r.be_u16(0);
        // `Field::opt`: değer yoksa (kısa paket) alan malformed olarak işaretlenir.
        l.push(Field::opt("echo.id", "Identifier", id.map(V::U16), r.abs(0), 2));
        let kind = r.u8(2);
        l.push(Field::opt("echo.kind", "Kind", kind.map(V::U8), r.abs(2), 1));
        if data.len() > 3 {
            l.push(Field::new(
                "echo.payload",
                format!("Payload ({} bytes)", data.len() - 3),
                V::Bytes { offset: r.abs(3), len: data.len() - 3 },
                r.abs(3),
                data.len() - 3,
            ));
        }
        ctx.info = Some(match (id, kind) {
            (Some(id), Some(k)) => format!("Echo id={id} kind={k}"),
            _ => "Echo (kısa)".to_owned(),
        });
        // Üstte başka protokol yoksa `last`. Varsa:
        // DissectResult::new(l, NextHint::Named("..."), payload_aralığı)
        DissectResult::last(l)
    }
}
```

Kurallar:

- `unwrap`/`expect`/indeksleme yerine `Reader` (`u8`, `be_u16`, `be_u32`, `slice`,
  `array`, `ipv4`, ...) ve `Option` kullanın. Lint'ler üretim kodunda
  `unwrap`/`expect` kullanımını reddeder.
- Okunamayan alanı atlamayın. `Field::opt` ile malformed alan ekleyin; katman
  bozuk görünür ve liste satırı `malformed` rengini alır.
- Alan adları `FIELDS` içinde tanımlı olmalıdır. Tanımsız bir adı filtre derleyicisi
  tanımaz.
- Zero-copy çalışın: yük için `V::Bytes { offset, len }` kullanın, kopyalamayın.

## 2. Kayıt: `crates/dissect/src/proto/mod.rs`

```rust
mod echo;
// ...
pub fn builtin() -> Vec<Box<dyn Dissector>> {
    vec![
        // ...
        Box::new(udp::Udp),
        // Uygulama katmanı: port tabanlılar önce, içerik sezgisi kullananlar (TLS, HTTP) sonra.
        Box::new(echo::Echo),
        // ...
    ]
}
```

Kayıt sırası eşleşme önceliğidir: `can_dissect` değeri `true` olan ilk dissector
kazanır. Port tabanlı dissector'ları içerik sezgisi kullananlardan (TLS, HTTP)
önce koyun. Başka bir yerde değişiklik gerekmez. `Registry::all_fields()` yeni
alanları filtre kataloğuna, otomatik tamamlamaya ve renklendirme kurallarına
otomatik olarak ekler.

## 3. Testler (aynı dosyanın sonunda)

```rust
#[cfg(test)]
pub(crate) mod tests {
    use crate::testutil::{dissect, sweep};
    use crate::FieldValue as V;

    // Ethernet + IPv4 + UDP (→ port 7) + ECHO (id=0x0102, kind=1, "hi").
    // Hex'i gerçek bir yakalamadan alın, ör. `tshark -x` veya `xxd -p`.
    pub(crate) const SAMPLE: &str = "…";

    #[test]
    fn basic() {
        let d = dissect(SAMPLE);
        assert_eq!(d.protocols(), ["frame", "eth", "ip", "udp", "echo"]);
        assert_eq!(d.summary.protocol, "ECHO");
        assert_eq!(d.summary.info, "Echo id=258 kind=1");
        assert_eq!(d.find("echo.id").unwrap().value, V::U16(0x0102));
        assert!(!d.layer("echo").unwrap().is_malformed());
    }

    /// Her önek uzunluğu için dissect: panic olmamalı, `frame` katmanı hep bulunmalı.
    #[test]
    fn truncation_sweep() {
        sweep(SAMPLE);
    }
}
```

Ardından örneği `proto/mod.rs` içindeki `mutation_smoke` listesine ekleyin
(`super::echo::tests::SAMPLE`). Bu test, ilk 42 bayttan sonrasını rastgele bozarak
500 kez dissect eder.

Filtreyle uçtan uca kontrol:

```sh
cargo test -p pakiz-dissect echo
cargo test --workspace
./target/debug/pakiz -r ornek.pcap --no-tui -Y 'echo.kind == 1'
```

## 4. Fuzz

`dissect_frame` hedefi tüm registry'yi kullanır, yani yeni dissector otomatik
olarak fuzz edilir:

```sh
cargo install cargo-fuzz
cd crates/dissect
mkdir -p fuzz/corpus/dissect_frame
xxd -r -p <<< "$SAMPLE_HEX" > fuzz/corpus/dissect_frame/echo   # isteğe bağlı tohum
cargo +nightly fuzz run dissect_frame -- -max_total_time=300
```

Çökme bulunursa girdi `fuzz/artifacts/dissect_frame/` altına yazılır. Girdiyi hex
olarak bir regresyon testine çevirip hatayı düzeltin. CI her push'ta hedefi 60 sn
çalıştırır.

## 5. Kontrol listesi

- [ ] `FIELDS` tüm alan adlarını içeriyor, adlar `<proto>.` önekiyle başlıyor
- [ ] `can_dissect` ucuz ve yanlış pozitifleri sınırlı
- [ ] Hiçbir yolda panic yok (`sweep` ve `mutation_smoke` geçiyor)
- [ ] `ctx.info` dolduruluyor (paket listesinin Info sütunu)
- [ ] `cargo clippy --workspace --all-targets -- -W clippy::pedantic -D warnings` temiz
- [ ] Gerekiyorsa README'deki protokol listesi güncellendi
