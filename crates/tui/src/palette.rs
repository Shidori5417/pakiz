//! Komut paleti: `:` satırı için filtrelenen aday listesi.

use crate::icons::IconSet;
use crate::theme::Theme;

/// (ad, argüman ipucu, açıklama).
pub const COMMANDS: [(&str, &str, &str); 9] = [
    ("w", "<dosya>", "gösterilen paketleri dosyaya yaz"),
    ("follow", "", "seçili akışı izle"),
    ("conv", "", "konuşmalar tablosu"),
    ("stats", "", "istatistikler"),
    ("packets", "", "paket listesine dön"),
    ("theme", "<ad>", "temayı değiştir"),
    ("layout", "<vertical|horizontal|zoom>", "panel düzeni"),
    ("icons", "<unicode|nerd|ascii>", "ikon seti"),
    ("q", "", "çık"),
];

/// Paletteki tek satır.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    /// Kabul edilince komut satırına yazılacak metin.
    pub text: String,
    /// Gösterilen ad (argüman ipucuyla).
    pub label: String,
    pub desc: String,
    /// Kabul sonrası komut çalıştırılabilir mi (argümanı eksik değil).
    pub complete: bool,
}

/// Eşleşme sırası: 0 önek, 1 alt dize, 2 alt dizi (fuzzy); `None` = eşleşmez.
fn score(query: &str, name: &str) -> Option<u8> {
    if query.is_empty() || name.starts_with(query) {
        return Some(0);
    }
    if name.contains(query) {
        return Some(1);
    }
    let mut it = name.chars();
    query.chars().all(|q| it.any(|c| c == q)).then_some(2)
}

fn ranked<'a>(query: &str, names: impl Iterator<Item = &'a str>) -> Vec<&'a str> {
    let q = query.to_lowercase();
    let mut v: Vec<(u8, &str)> = names.filter_map(|n| score(&q, n).map(|s| (s, n))).collect();
    v.sort_by_key(|&(s, _)| s);
    v.into_iter().map(|(_, n)| n).collect()
}

/// `text` için aday listesi (komut adları, ya da `theme`/`layout`/`icons` argümanları).
#[must_use]
pub fn candidates(text: &str) -> Vec<Candidate> {
    let t = text.trim_start();
    if let Some((cmd, arg)) = t.split_once(char::is_whitespace) {
        let arg = arg.trim_start();
        let choices: Vec<&str> = match cmd {
            "theme" => Theme::NAMES.to_vec(),
            "layout" => vec!["vertical", "horizontal", "zoom"],
            "icons" => IconSet::NAMES.to_vec(),
            "w" => {
                return vec![Candidate {
                    text: format!("w {arg}"),
                    label: "w <dosya>".into(),
                    desc: "dosya adını yazıp Enter".into(),
                    complete: !arg.is_empty(),
                }];
            }
            _ => return Vec::new(),
        };
        return ranked(arg, choices.into_iter())
            .into_iter()
            .map(|n| Candidate {
                text: format!("{cmd} {n}"),
                label: format!("{cmd} {n}"),
                desc: COMMANDS
                    .iter()
                    .find(|(c, ..)| *c == cmd)
                    .map_or_else(String::new, |(.., d)| (*d).to_owned()),
                complete: true,
            })
            .collect();
    }
    ranked(t, COMMANDS.iter().map(|(n, ..)| *n))
        .into_iter()
        .filter_map(|n| COMMANDS.iter().find(|(c, ..)| *c == n))
        .map(|&(n, args, desc)| Candidate {
            text: if args.is_empty() {
                n.to_owned()
            } else {
                format!("{n} ")
            },
            label: if args.is_empty() {
                n.to_owned()
            } else {
                format!("{n} {args}")
            },
            desc: desc.to_owned(),
            complete: args.is_empty(),
        })
        .collect()
}
