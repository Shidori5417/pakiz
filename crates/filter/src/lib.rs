//! pakiz-filter: Wireshark tarzı display filter ve yakalama (BPF) filtresi.
//!
//! ```text
//! expr    := or
//! or      := and (("||" | "or") and)*
//! and     := unary (("&&" | "and") unary)*
//! unary   := ("!" | "not") unary | "(" expr ")" | field [cmp value]
//! cmp     := == != > < >= <= eq ne gt lt ge le contains matches ~
//! value   := sayı (10, 0x1f) | "string" | IPv4[/n] | IPv6[/n] | aa:bb:.. | true | false
//! ```
//!
//! Tek başına alan adı (`tcp`, `tcp.options`) varlık sınamasıdır.
#![cfg_attr(test, allow(clippy::unwrap_used))]

use std::ops::Range;

pub mod bpf;
mod compile;
pub mod lexer;
pub mod parser;

pub use compile::{complete, levenshtein, validate, FieldCatalog, Filter};
pub use lexer::CmpOp;
pub use parser::{parse, Expr, FieldRef, Literal};

/// Konumlu filtre hatası (`span` kaynakta bayt ofseti aralığı).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{msg} (konum {}..{})", span.start, span.end)]
pub struct FilterError {
    pub span: Range<usize>,
    pub msg: String,
}

impl FilterError {
    #[must_use]
    pub fn new(span: Range<usize>, msg: impl Into<String>) -> Self {
        Self {
            span,
            msg: msg.into(),
        }
    }
}
