//! Elle yazılmış display filter lexer'ı.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::ops::Range;

use crate::FilterError;

/// Karşılaştırma operatörü.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CmpOp {
    Eq,
    Ne,
    Gt,
    Lt,
    Ge,
    Le,
    Contains,
    Matches,
}

/// Sözcük birimi türü.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Tok {
    /// Alan adı veya `true`/`false` gibi çıplak kelime.
    Ident(String),
    Number(u64),
    Str(String),
    Ipv4 {
        addr: Ipv4Addr,
        prefix: u8,
    },
    Ipv6 {
        addr: Ipv6Addr,
        prefix: u8,
    },
    /// `aa:bb:cc` biçimli bayt dizisi (MAC = 6 bayt).
    Bytes(Vec<u8>),
    Cmp(CmpOp),
    And,
    Or,
    Not,
    LParen,
    RParen,
}

/// Konumlu sözcük birimi (bayt ofseti aralığı).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Token {
    pub tok: Tok,
    pub span: Range<usize>,
}

fn word_char(c: u8) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'-' | b':' | b'/')
}

/// Kaynağı sözcük birimlerine ayırır.
///
/// # Errors
/// Geçersiz karakter, kapanmamış string veya bozuk adres/sayı.
pub fn lex(src: &str) -> Result<Vec<Token>, FilterError> {
    let b = src.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        if c.is_ascii_whitespace() {
            i += 1;
            continue;
        }
        let start = i;
        let two = b.get(i..i + 2);
        let (tok, len) = match (c, two) {
            (_, Some(b"==")) => (Tok::Cmp(CmpOp::Eq), 2),
            (_, Some(b"!=")) => (Tok::Cmp(CmpOp::Ne), 2),
            (_, Some(b">=")) => (Tok::Cmp(CmpOp::Ge), 2),
            (_, Some(b"<=")) => (Tok::Cmp(CmpOp::Le), 2),
            (_, Some(b"&&")) => (Tok::And, 2),
            (_, Some(b"||")) => (Tok::Or, 2),
            (b'>', _) => (Tok::Cmp(CmpOp::Gt), 1),
            (b'<', _) => (Tok::Cmp(CmpOp::Lt), 1),
            (b'!', _) => (Tok::Not, 1),
            (b'~', _) => (Tok::Cmp(CmpOp::Matches), 1),
            (b'(', _) => (Tok::LParen, 1),
            (b')', _) => (Tok::RParen, 1),
            (b'"', _) => {
                let (s, end) = lex_string(src, i)?;
                (Tok::Str(s), end - i)
            }
            _ if word_char(c) => {
                let mut j = i;
                while j < b.len() && word_char(b[j]) {
                    j += 1;
                }
                (classify(&src[i..j], i..j)?, j - i)
            }
            _ => {
                let ch = src[i..].chars().next().unwrap_or('?');
                return Err(FilterError::new(
                    i..i + ch.len_utf8(),
                    format!("beklenmeyen karakter: '{ch}'"),
                ));
            }
        };
        i += len;
        out.push(Token {
            tok,
            span: start..i,
        });
    }
    Ok(out)
}

/// `"..."` string'i; `\"` ve `\\` kaçışları. Bitiş ofsetini döner.
fn lex_string(src: &str, start: usize) -> Result<(String, usize), FilterError> {
    let mut s = String::new();
    let mut chars = src[start + 1..].char_indices();
    while let Some((k, ch)) = chars.next() {
        match ch {
            '"' => return Ok((s, start + 1 + k + 1)),
            '\\' => match chars.next() {
                Some((_, e @ ('"' | '\\'))) => s.push(e),
                Some((k2, e)) => {
                    let at = start + 1 + k2;
                    return Err(FilterError::new(
                        at - 1..at + e.len_utf8(),
                        format!("geçersiz kaçış: \\{e}"),
                    ));
                }
                None => break,
            },
            _ => s.push(ch),
        }
    }
    Err(FilterError::new(start..src.len(), "kapanmamış string"))
}

fn keyword(w: &str) -> Option<Tok> {
    Some(match w {
        "and" => Tok::And,
        "or" => Tok::Or,
        "not" => Tok::Not,
        "eq" => Tok::Cmp(CmpOp::Eq),
        "ne" => Tok::Cmp(CmpOp::Ne),
        "gt" => Tok::Cmp(CmpOp::Gt),
        "lt" => Tok::Cmp(CmpOp::Lt),
        "ge" => Tok::Cmp(CmpOp::Ge),
        "le" => Tok::Cmp(CmpOp::Le),
        "contains" => Tok::Cmp(CmpOp::Contains),
        "matches" => Tok::Cmp(CmpOp::Matches),
        _ => return None,
    })
}

fn classify(w: &str, span: Range<usize>) -> Result<Tok, FilterError> {
    if let Some(k) = keyword(w) {
        return Ok(k);
    }
    let bad = |what: &str| FilterError::new(span.clone(), format!("geçersiz {what}: {w}"));
    let first = w.as_bytes()[0];
    if w.contains(':') {
        return lex_colon(w).ok_or_else(|| bad("adres"));
    }
    if first.is_ascii_alphabetic() || first == b'_' {
        if w.contains('/') {
            return Err(bad("tanımlayıcı"));
        }
        return Ok(Tok::Ident(w.to_owned()));
    }
    if let Some(n) = parse_number(w) {
        return Ok(Tok::Number(n));
    }
    if first.is_ascii_digit() && w.contains('.') {
        let (a, p) = split_prefix(w, 32).ok_or_else(|| bad("önek"))?;
        let addr: Ipv4Addr = a.parse().map_err(|_| bad("IPv4 adresi"))?;
        return Ok(Tok::Ipv4 { addr, prefix: p });
    }
    Err(bad("değer"))
}

/// Ondalık veya `0x` onaltılık sayı.
pub(crate) fn parse_number(w: &str) -> Option<u64> {
    if let Some(h) = w.strip_prefix("0x").or_else(|| w.strip_prefix("0X")) {
        return u64::from_str_radix(h, 16).ok();
    }
    if w.bytes().all(|c| c.is_ascii_digit()) {
        return w.parse().ok();
    }
    None
}

fn split_prefix(w: &str, max: u8) -> Option<(&str, u8)> {
    match w.split_once('/') {
        None => Some((w, max)),
        Some((a, p)) => {
            let p: u8 = p.parse().ok()?;
            (p <= max).then_some((a, p))
        }
    }
}

/// `:` içeren kelime: tüm gruplar 2 hane ise bayt dizisi, değilse IPv6.
fn lex_colon(w: &str) -> Option<Tok> {
    let groups: Vec<&str> = w.split(':').collect();
    if !w.contains('/')
        && groups.len() >= 2
        && groups
            .iter()
            .all(|g| g.len() == 2 && g.bytes().all(|c| c.is_ascii_hexdigit()))
    {
        let bytes = groups
            .iter()
            .map(|g| u8::from_str_radix(g, 16).ok())
            .collect::<Option<Vec<u8>>>()?;
        return Some(Tok::Bytes(bytes));
    }
    let (a, prefix) = split_prefix(w, 128)?;
    let addr: Ipv6Addr = a.parse().ok()?;
    Some(Tok::Ipv6 { addr, prefix })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn toks(s: &str) -> Vec<Tok> {
        lex(s).unwrap().into_iter().map(|t| t.tok).collect()
    }

    #[test]
    fn idents_and_ops() {
        assert_eq!(
            toks("tcp.flags.syn==1&&!arp||x_y-z"),
            vec![
                Tok::Ident("tcp.flags.syn".into()),
                Tok::Cmp(CmpOp::Eq),
                Tok::Number(1),
                Tok::And,
                Tok::Not,
                Tok::Ident("arp".into()),
                Tok::Or,
                Tok::Ident("x_y-z".into()),
            ]
        );
    }

    #[test]
    fn all_operators_and_words() {
        let sym = toks("== != > < >= <= && || ! ~ ( )");
        let words = toks("eq ne gt lt ge le and or not matches");
        assert_eq!(sym.len(), 12);
        assert_eq!(&sym[..6], &words[..6]);
        assert_eq!(&sym[6..9], &words[6..9]);
        assert_eq!(sym[9], words[9]);
        assert_eq!(toks("contains"), vec![Tok::Cmp(CmpOp::Contains)]);
        assert_eq!(sym[10..], [Tok::LParen, Tok::RParen]);
    }

    #[test]
    fn numbers() {
        assert_eq!(
            toks("0 1000 0x1F 0XfF"),
            vec![
                Tok::Number(0),
                Tok::Number(1000),
                Tok::Number(31),
                Tok::Number(255)
            ]
        );
        assert!(lex("12abc").is_err());
        assert!(lex("0xzz").is_err());
    }

    #[test]
    fn strings_with_escapes() {
        assert_eq!(
            toks(r#""a\"b\\c" "x""#),
            vec![Tok::Str("a\"b\\c".into()), Tok::Str("x".into())]
        );
        let e = lex(r#"a == "abc"#).unwrap_err();
        assert_eq!(e.span, 5..9);
        let e = lex(r#""a\n""#).unwrap_err();
        assert_eq!(e.span, 2..4);
    }

    #[test]
    fn addresses() {
        assert_eq!(
            toks("10.0.0.1 10.0.0.0/8"),
            vec![
                Tok::Ipv4 {
                    addr: Ipv4Addr::new(10, 0, 0, 1),
                    prefix: 32
                },
                Tok::Ipv4 {
                    addr: Ipv4Addr::new(10, 0, 0, 0),
                    prefix: 8
                },
            ]
        );
        assert_eq!(
            toks("fe80::1 2001:db8::/32"),
            vec![
                Tok::Ipv6 {
                    addr: "fe80::1".parse().unwrap(),
                    prefix: 128
                },
                Tok::Ipv6 {
                    addr: "2001:db8::".parse().unwrap(),
                    prefix: 32
                },
            ]
        );
        assert_eq!(
            toks("aa:bb:cc:dd:ee:ff 01:02"),
            vec![
                Tok::Bytes(vec![0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]),
                Tok::Bytes(vec![1, 2])
            ]
        );
        assert!(lex("10.0.0.256").is_err());
        assert!(lex("10.0.0.0/33").is_err());
        assert!(lex("zz:zz").is_err());
    }

    #[test]
    fn spans_and_bad_char() {
        let t = lex("  ip.src  == 1").unwrap();
        assert_eq!(t[0].span, 2..8);
        assert_eq!(t[1].span, 10..12);
        assert_eq!(t[2].span, 13..14);
        let e = lex("a # b").unwrap_err();
        assert_eq!(e.span, 2..3);
        let e = lex("a ç").unwrap_err();
        assert_eq!(e.span, 2..4);
    }
}
