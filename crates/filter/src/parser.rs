//! Pratt parser: sözcük birimlerinden AST üretir.
//!
//! Öncelik (yüksekten düşüğe): karşılaştırma > `!` > `&&` > `||`.

use std::ops::Range;

use crate::lexer::{lex, CmpOp, Tok, Token};
use crate::FilterError;

/// Konumlu alan adı.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldRef {
    pub name: String,
    pub span: Range<usize>,
}

/// Karşılaştırmanın sağ tarafı (henüz alan tipine göre yorumlanmamış).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Literal {
    pub tok: Tok,
    pub span: Range<usize>,
}

/// Filtre ifadesi.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Expr {
    And(Box<Expr>, Box<Expr>),
    Or(Box<Expr>, Box<Expr>),
    Not(Box<Expr>),
    /// Alan/protokol pakette var mı?
    Exists(FieldRef),
    Compare {
        field: FieldRef,
        op: CmpOp,
        value: Literal,
    },
}

const OR_BP: u8 = 1;
const AND_BP: u8 = 2;
const NOT_BP: u8 = 3;

/// Kaynağı AST'ye çevirir.
///
/// # Errors
/// Lexer hatası, beklenmeyen/eksik sözcük birimi.
pub fn parse(src: &str) -> Result<Expr, FilterError> {
    let tokens = lex(src)?;
    let mut p = Parser {
        tokens,
        pos: 0,
        end: src.len(),
    };
    if p.tokens.is_empty() {
        return Err(FilterError::new(0..src.len(), "boş filtre"));
    }
    let e = p.expr(0)?;
    if let Some(t) = p.peek() {
        return Err(FilterError::new(
            t.span.clone(),
            "beklenmeyen sözcük: ifade sonu bekleniyordu",
        ));
    }
    Ok(e)
}

struct Parser {
    tokens: Vec<Token>,
    pos: usize,
    end: usize,
}

impl Parser {
    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.pos)
    }

    fn next(&mut self) -> Result<Token, FilterError> {
        let t = self
            .tokens
            .get(self.pos)
            .cloned()
            .ok_or_else(|| FilterError::new(self.end..self.end, "beklenmedik ifade sonu"))?;
        self.pos += 1;
        Ok(t)
    }

    fn expr(&mut self, min_bp: u8) -> Result<Expr, FilterError> {
        let mut lhs = self.prefix()?;
        loop {
            let (bp, and) = match self.peek().map(|t| &t.tok) {
                Some(Tok::And) => (AND_BP, true),
                Some(Tok::Or) => (OR_BP, false),
                _ => break,
            };
            if bp <= min_bp {
                break;
            }
            self.pos += 1;
            let rhs = self.expr(bp)?;
            lhs = if and {
                Expr::And(Box::new(lhs), Box::new(rhs))
            } else {
                Expr::Or(Box::new(lhs), Box::new(rhs))
            };
        }
        Ok(lhs)
    }

    fn prefix(&mut self) -> Result<Expr, FilterError> {
        let t = self.next()?;
        match t.tok {
            Tok::Not => Ok(Expr::Not(Box::new(self.expr(NOT_BP - 1)?))),
            Tok::LParen => {
                let e = self.expr(0)?;
                match self.next() {
                    Ok(Token {
                        tok: Tok::RParen, ..
                    }) => Ok(e),
                    Ok(other) => Err(FilterError::new(other.span, "')' bekleniyordu")),
                    Err(_) => Err(FilterError::new(t.span, "kapanmamış parantez")),
                }
            }
            Tok::Ident(name) => {
                let field = FieldRef { name, span: t.span };
                let Some(Tok::Cmp(op)) = self.peek().map(|t| &t.tok) else {
                    return Ok(Expr::Exists(field));
                };
                let op = *op;
                self.pos += 1;
                let v = self.next()?;
                if !matches!(
                    v.tok,
                    Tok::Ident(_)
                        | Tok::Number(_)
                        | Tok::Str(_)
                        | Tok::Ipv4 { .. }
                        | Tok::Ipv6 { .. }
                        | Tok::Bytes(_)
                ) {
                    return Err(FilterError::new(v.span, "değer bekleniyordu"));
                }
                Ok(Expr::Compare {
                    field,
                    op,
                    value: Literal {
                        tok: v.tok,
                        span: v.span,
                    },
                })
            }
            _ => Err(FilterError::new(
                t.span,
                "alan adı, '!' veya '(' bekleniyordu",
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// AST'yi kısa, öncelikleri gösteren metne çevirir.
    fn show(e: &Expr) -> String {
        match e {
            Expr::And(a, b) => format!("({} && {})", show(a), show(b)),
            Expr::Or(a, b) => format!("({} || {})", show(a), show(b)),
            Expr::Not(a) => format!("!{}", show(a)),
            Expr::Exists(f) => f.name.clone(),
            Expr::Compare { field, op, value } => format!("{}{op:?}{:?}", field.name, value.tok),
        }
    }

    fn p(s: &str) -> String {
        show(&parse(s).unwrap())
    }

    #[test]
    fn precedence() {
        assert_eq!(p("a || b && c"), "(a || (b && c))");
        assert_eq!(p("a && b || c"), "((a && b) || c)");
        assert_eq!(p("!a && b"), "(!a && b)");
        assert_eq!(p("not a or b and not c"), "(!a || (b && !c))");
        assert_eq!(p("a && b && c"), "((a && b) && c)");
        assert_eq!(p("a || b || c"), "((a || b) || c)");
    }

    #[test]
    fn parens() {
        assert_eq!(p("(a || b) && c"), "((a || b) && c)");
        assert_eq!(p("!(a || b)"), "!(a || b)");
        assert_eq!(p("((a))"), "a");
    }

    #[test]
    fn comparisons() {
        assert_eq!(p("tcp.flags.syn == 1"), "tcp.flags.synEqNumber(1)");
        assert_eq!(p("frame.len gt 1000"), "frame.lenGtNumber(1000)");
        assert_eq!(p("!x.y ~ \"a\" && z"), "(!x.yMatchesStr(\"a\") && z)");
        assert_eq!(p("dns || http"), "(dns || http)");
    }

    #[test]
    fn errors_with_spans() {
        let e = parse("tcp &&").unwrap_err();
        assert_eq!(e.span, 6..6);
        let e = parse("(tcp").unwrap_err();
        assert_eq!(e.span, 0..1);
        assert!(e.msg.contains("parantez"));
        let e = parse("tcp udp").unwrap_err();
        assert_eq!(e.span, 4..7);
        let e = parse("a == ==").unwrap_err();
        assert_eq!(e.span, 5..7);
        let e = parse("== 1").unwrap_err();
        assert_eq!(e.span, 0..2);
        let e = parse("(a b)").unwrap_err();
        assert_eq!(e.span, 3..4);
        assert!(parse("").is_err());
        assert!(parse("   ").is_err());
        assert!(parse("a ==").is_err());
    }
}
