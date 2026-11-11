//! Alan kataloğu, derleme (tip denetimi + literal ön-ayrıştırma) ve değerlendirme.

use std::collections::HashMap;

use pakiz_dissect::{Dissection, Field, FieldDef, FieldType, FieldValue, RawPacket, Registry};
use regex::Regex;

use crate::lexer::{CmpOp, Tok};
use crate::parser::{parse, Expr, FieldRef, Literal};
use crate::FilterError;

/// Filtrede kullanılabilen alanlar (ada göre sıralı).
#[derive(Debug, Clone)]
pub struct FieldCatalog {
    defs: Vec<FieldDef>,
    index: HashMap<&'static str, usize>,
}

impl Default for FieldCatalog {
    fn default() -> Self {
        Self::from_registry(&Registry::default())
    }
}

impl FieldCatalog {
    /// Verilen tanımlardan katalog kurar; alan adlarının ilk bileşeni
    /// (`tcp.port` → `tcp`) tanımlı değilse protokol olarak eklenir.
    #[must_use]
    pub fn new(mut defs: Vec<FieldDef>) -> Self {
        let protos: Vec<&'static str> = defs
            .iter()
            .filter_map(|d| d.name.split_once('.').map(|(p, _)| p))
            .collect();
        for p in protos {
            if !defs.iter().any(|d| d.name == p) {
                defs.push(FieldDef::new(p, FieldType::None, "Protocol"));
            }
        }
        defs.sort_by(|a, b| a.name.cmp(b.name));
        defs.dedup_by(|a, b| a.name == b.name);
        let index = defs.iter().enumerate().map(|(i, d)| (d.name, i)).collect();
        Self { defs, index }
    }

    /// `Registry::all_fields()` + protokol adları.
    #[must_use]
    pub fn from_registry(reg: &Registry) -> Self {
        Self::new(reg.all_fields())
    }

    #[must_use]
    pub fn get(&self, name: &str) -> Option<&FieldDef> {
        self.index.get(name).map(|&i| &self.defs[i])
    }

    /// Ada göre sıralı tüm alanlar.
    #[must_use]
    pub fn fields(&self) -> &[FieldDef] {
        &self.defs
    }

    /// Levenshtein uzaklığına göre en yakın alan adı (makul uzaklıktaysa).
    #[must_use]
    pub fn suggest(&self, name: &str) -> Option<&'static str> {
        let max = (name.chars().count() / 3).max(2);
        self.defs
            .iter()
            .map(|d| (levenshtein(name, d.name), d.name))
            .filter(|&(dist, _)| dist <= max)
            .min_by_key(|&(dist, n)| (dist, n.len().abs_diff(name.len()), n))
            .map(|(_, n)| n)
    }
}

/// Basit Levenshtein (karakter bazlı).
#[must_use]
pub fn levenshtein(a: &str, b: &str) -> usize {
    // Optimal string alignment: bitişik harf yer değiştirmesi (tpc → tcp) 1 sayılır.
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let mut d = vec![vec![0usize; b.len() + 1]; a.len() + 1];
    for (i, row) in d.iter_mut().enumerate() {
        row[0] = i;
    }
    for (j, cell) in d[0].iter_mut().enumerate() {
        *cell = j;
    }
    for i in 1..=a.len() {
        for j in 1..=b.len() {
            let cost = usize::from(a[i - 1] != b[j - 1]);
            let mut v = (d[i - 1][j] + 1)
                .min(d[i][j - 1] + 1)
                .min(d[i - 1][j - 1] + cost);
            if i > 1 && j > 1 && a[i - 1] == b[j - 2] && a[i - 2] == b[j - 1] {
                v = v.min(d[i - 2][j - 2] + 1);
            }
            d[i][j] = v;
        }
    }
    d[a.len()][b.len()]
}

/// `prefix` ile başlayan alanlar, ada göre sıralı (otomatik tamamlama).
#[must_use]
pub fn complete<'a>(prefix: &str, catalog: &'a FieldCatalog) -> Vec<&'a FieldDef> {
    let start = catalog.defs.partition_point(|d| d.name < prefix);
    catalog.defs[start..]
        .iter()
        .take_while(|d| d.name.starts_with(prefix))
        .collect()
}

/// Kaynağı derler ama filtreyi atar (TUI canlı renklendirme için).
///
/// # Errors
/// [`Filter::compile`] ile aynı.
pub fn validate(src: &str, catalog: &FieldCatalog) -> Result<(), FilterError> {
    Filter::compile(src, catalog).map(|_| ())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Ord3 {
    Eq,
    Ne,
    Gt,
    Lt,
    Ge,
    Le,
}

impl Ord3 {
    fn test<T: PartialOrd>(self, a: &T, b: &T) -> bool {
        match self {
            Self::Eq => a == b,
            Self::Ne => a != b,
            Self::Gt => a > b,
            Self::Lt => a < b,
            Self::Ge => a >= b,
            Self::Le => a <= b,
        }
    }
}

/// Önceden ayrıştırılmış koşul.
#[derive(Debug, Clone)]
enum Pred {
    Exists,
    Num(Ord3, u64),
    Ipv4 { op: Ord3, net: u32, mask: u32 },
    Ipv6 { op: Ord3, net: u128, mask: u128 },
    Mac(Ord3, [u8; 6]),
    Str(Ord3, String),
    StrContains(String),
    Regex(Regex),
    Bytes(Ord3, Vec<u8>),
    BytesContains(Vec<u8>),
}

#[derive(Debug, Clone)]
enum Node {
    And(Box<Node>, Box<Node>),
    Or(Box<Node>, Box<Node>),
    Not(Box<Node>),
    /// `names` içindeki alanlardan herhangi bir örneği `pred`'i sağlarsa true.
    Test {
        names: &'static [&'static str],
        single: [&'static str; 1],
        pred: Pred,
    },
}

/// Derlenmiş display filter.
#[derive(Debug, Clone)]
pub struct Filter {
    root: Node,
}

impl Filter {
    /// Kaynağı derler: alan adları katalogda çözülür, literal'ler alan tipine
    /// göre bir kez ayrıştırılır (IP, sayı, regex).
    ///
    /// # Errors
    /// Sözdizimi hatası, bilinmeyen alan, tip uyuşmazlığı, geçersiz regex.
    pub fn compile(src: &str, catalog: &FieldCatalog) -> Result<Self, FilterError> {
        let ast = parse(src)?;
        Ok(Self {
            root: lower(&ast, catalog)?,
        })
    }

    /// Paket filtreyi sağlıyor mu? `pkt`, `Bytes` alanlarının içeriği için gerekir.
    ///
    /// Bir alan birden çok kez geçebilir (VLAN, sanal `*.addr`/`*.port`):
    /// herhangi bir örnek koşulu sağlarsa true. Bu yüzden `!=` de "herhangi
    /// biri eşit değil" anlamındadır (`ip.addr != 1.2.3.4`, kaynak veya hedef
    /// farklıysa true); "hiçbiri eşit değil" için `!(ip.addr == 1.2.3.4)`.
    #[must_use]
    pub fn matches(&self, d: &Dissection, pkt: &RawPacket) -> bool {
        eval(&self.root, d, &pkt.data)
    }
}

fn eval(n: &Node, d: &Dissection, data: &[u8]) -> bool {
    match n {
        Node::And(a, b) => eval(a, d, data) && eval(b, d, data),
        Node::Or(a, b) => eval(a, d, data) || eval(b, d, data),
        Node::Not(a) => !eval(a, d, data),
        Node::Test {
            names,
            single,
            pred,
        } => {
            let names: &[&str] = if names.is_empty() { single } else { names };
            d.layers
                .iter()
                .any(|l| any_field(&l.fields, names, pred, data))
        }
    }
}

fn any_field(f: &Field, names: &[&str], pred: &Pred, data: &[u8]) -> bool {
    (names.contains(&f.name) && check(pred, &f.value, data))
        || f.children.iter().any(|c| any_field(c, names, pred, data))
}

fn check(pred: &Pred, v: &FieldValue, data: &[u8]) -> bool {
    match pred {
        Pred::Exists => true,
        Pred::Num(op, k) => v.as_u64().is_some_and(|x| op.test(&x, k)),
        Pred::Ipv4 { op, net, mask } => match v {
            FieldValue::Ipv4(a) => cmp_net(*op, u32::from(*a), *net, *mask),
            _ => false,
        },
        Pred::Ipv6 { op, net, mask } => match v {
            FieldValue::Ipv6(a) => cmp_net(*op, u128::from(*a), *net, *mask),
            _ => false,
        },
        Pred::Mac(op, m) => matches!(v, FieldValue::Mac(a) if op.test(a, m)),
        Pred::Str(op, s) => matches!(v, FieldValue::Str(a) if op.test(&a.as_ref(), &s.as_str())),
        Pred::StrContains(s) => match v {
            FieldValue::Str(a) => a.contains(s.as_str()),
            _ => bytes_of(v, data).is_some_and(|b| contains(b, s.as_bytes())),
        },
        Pred::Regex(r) => matches!(v, FieldValue::Str(a) if r.is_match(a)),
        Pred::Bytes(op, b) => bytes_of(v, data).is_some_and(|a| op.test(&a, &b.as_slice())),
        Pred::BytesContains(b) => bytes_of(v, data).is_some_and(|a| contains(a, b)),
    }
}

fn cmp_net<T>(op: Ord3, a: T, net: T, mask: T) -> bool
where
    T: Copy + PartialOrd + std::ops::BitAnd<Output = T>,
{
    match op {
        Ord3::Eq => a & mask == net,
        Ord3::Ne => a & mask != net,
        _ => op.test(&a, &net),
    }
}

fn bytes_of<'a>(v: &FieldValue, data: &'a [u8]) -> Option<&'a [u8]> {
    match *v {
        FieldValue::Bytes { offset, len } => data.get(offset..offset.checked_add(len)?),
        _ => None,
    }
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    needle.is_empty() || hay.windows(needle.len()).any(|w| w == needle)
}

fn resolve(f: &FieldRef, catalog: &FieldCatalog) -> Result<FieldDef, FilterError> {
    catalog.get(&f.name).copied().ok_or_else(|| {
        let mut msg = format!("bilinmeyen alan: {}", f.name);
        if let Some(s) = catalog.suggest(&f.name) {
            msg = format!("{msg} (bunu mu demek istediniz: {s}?)");
        }
        FilterError::new(f.span.clone(), msg)
    })
}

fn test_node(def: &FieldDef, pred: Pred) -> Node {
    Node::Test {
        names: def.alias_of,
        single: [def.name],
        pred,
    }
}

fn lower(e: &Expr, cat: &FieldCatalog) -> Result<Node, FilterError> {
    Ok(match e {
        Expr::And(a, b) => Node::And(Box::new(lower(a, cat)?), Box::new(lower(b, cat)?)),
        Expr::Or(a, b) => Node::Or(Box::new(lower(a, cat)?), Box::new(lower(b, cat)?)),
        Expr::Not(a) => Node::Not(Box::new(lower(a, cat)?)),
        Expr::Exists(f) => test_node(&resolve(f, cat)?, Pred::Exists),
        Expr::Compare { field, op, value } => {
            let def = resolve(field, cat)?;
            test_node(&def, pred_for(&def, *op, value)?)
        }
    })
}

fn type_name(t: FieldType) -> &'static str {
    match t {
        FieldType::U8 | FieldType::U16 | FieldType::U32 | FieldType::U64 => "sayı",
        FieldType::Bool => "bool",
        FieldType::Bytes => "bayt dizisi",
        FieldType::Str => "string",
        FieldType::Ipv4 => "IPv4 adresi",
        FieldType::Ipv6 => "IPv6 adresi",
        FieldType::Mac => "MAC adresi",
        FieldType::Time => "zaman",
        FieldType::None => "protokol",
    }
}

fn mask32(prefix: u8) -> u32 {
    u32::MAX.checked_shl(32 - u32::from(prefix)).unwrap_or(0)
}

fn mask128(prefix: u8) -> u128 {
    u128::MAX.checked_shl(128 - u32::from(prefix)).unwrap_or(0)
}

// Tip başına tek bir eşleme tablosu; bölmek okunurluğu azaltır.
#[allow(clippy::too_many_lines)]
fn pred_for(def: &FieldDef, op: CmpOp, lit: &Literal) -> Result<Pred, FilterError> {
    let err = |m: String| FilterError::new(lit.span.clone(), m);
    let mismatch = || {
        err(format!(
            "{} alanı {} ile karşılaştırılamaz",
            def.name,
            lit_name(&lit.tok)
        ))
    };
    let ord = match op {
        CmpOp::Eq => Some(Ord3::Eq),
        CmpOp::Ne => Some(Ord3::Ne),
        CmpOp::Gt => Some(Ord3::Gt),
        CmpOp::Lt => Some(Ord3::Lt),
        CmpOp::Ge => Some(Ord3::Ge),
        CmpOp::Le => Some(Ord3::Le),
        CmpOp::Contains | CmpOp::Matches => None,
    };
    let eq_only = |o: Ord3| -> Result<Ord3, FilterError> {
        if matches!(o, Ord3::Eq | Ord3::Ne) {
            Ok(o)
        } else {
            Err(err(format!(
                "{} ({}) için yalnızca == ve != kullanılabilir",
                def.name,
                type_name(def.ty)
            )))
        }
    };
    let bad_op = || {
        err(format!(
            "{op:?} operatörü {} ({}) için kullanılamaz",
            def.name,
            type_name(def.ty)
        ))
    };
    match def.ty {
        FieldType::U8 | FieldType::U16 | FieldType::U32 | FieldType::U64 => {
            let o = ord.ok_or_else(bad_op)?;
            let Tok::Number(n) = lit.tok else {
                return Err(mismatch());
            };
            let max = match def.ty {
                FieldType::U8 => u64::from(u8::MAX),
                FieldType::U16 => u64::from(u16::MAX),
                FieldType::U32 => u64::from(u32::MAX),
                _ => u64::MAX,
            };
            if n > max {
                return Err(err(format!("{n} değeri {} için aralık dışında", def.name)));
            }
            Ok(Pred::Num(o, n))
        }
        FieldType::Bool => {
            let o = eq_only(ord.ok_or_else(bad_op)?)?;
            let b = match &lit.tok {
                Tok::Number(0) => 0,
                Tok::Number(1) => 1,
                Tok::Ident(w) if w == "true" => 1,
                Tok::Ident(w) if w == "false" => 0,
                _ => {
                    return Err(err(format!(
                        "{} için 0/1 veya true/false bekleniyordu",
                        def.name
                    )))
                }
            };
            Ok(Pred::Num(o, b))
        }
        FieldType::Ipv4 => {
            let o = ord.ok_or_else(bad_op)?;
            let Tok::Ipv4 { addr, prefix } = lit.tok else {
                return Err(mismatch());
            };
            if prefix != 32 && !matches!(o, Ord3::Eq | Ord3::Ne) {
                return Err(err("CIDR ile yalnızca == ve != kullanılabilir".into()));
            }
            let mask = mask32(prefix);
            Ok(Pred::Ipv4 {
                op: o,
                net: u32::from(addr) & mask,
                mask,
            })
        }
        FieldType::Ipv6 => {
            let o = ord.ok_or_else(bad_op)?;
            let Tok::Ipv6 { addr, prefix } = lit.tok else {
                return Err(mismatch());
            };
            if prefix != 128 && !matches!(o, Ord3::Eq | Ord3::Ne) {
                return Err(err("CIDR ile yalnızca == ve != kullanılabilir".into()));
            }
            let mask = mask128(prefix);
            Ok(Pred::Ipv6 {
                op: o,
                net: u128::from(addr) & mask,
                mask,
            })
        }
        FieldType::Mac => {
            let o = eq_only(ord.ok_or_else(bad_op)?)?;
            match &lit.tok {
                Tok::Bytes(b) => {
                    let m: [u8; 6] = b
                        .as_slice()
                        .try_into()
                        .map_err(|_| err("MAC adresi 6 bayt olmalı".into()))?;
                    Ok(Pred::Mac(o, m))
                }
                _ => Err(mismatch()),
            }
        }
        FieldType::Str => match (op, &lit.tok) {
            (CmpOp::Contains, Tok::Str(s)) => Ok(Pred::StrContains(s.clone())),
            (CmpOp::Matches, Tok::Str(s)) => Regex::new(s)
                .map(Pred::Regex)
                .map_err(|e| err(format!("geçersiz regex: {e}"))),
            (_, Tok::Str(s)) => Ok(Pred::Str(eq_only(ord.ok_or_else(bad_op)?)?, s.clone())),
            _ => Err(mismatch()),
        },
        FieldType::Bytes => {
            let bytes = match &lit.tok {
                Tok::Bytes(b) => b.clone(),
                Tok::Str(s) => s.as_bytes().to_vec(),
                _ => return Err(mismatch()),
            };
            match op {
                CmpOp::Contains => Ok(Pred::BytesContains(bytes)),
                CmpOp::Matches => Err(bad_op()),
                _ => Ok(Pred::Bytes(eq_only(ord.ok_or_else(bad_op)?)?, bytes)),
            }
        }
        FieldType::Time | FieldType::None => Err(err(format!(
            "{} ({}) karşılaştırılamaz, yalnızca varlığı sınanabilir",
            def.name,
            type_name(def.ty)
        ))),
    }
}

fn lit_name(t: &Tok) -> &'static str {
    match t {
        Tok::Number(_) => "sayı",
        Tok::Str(_) => "string",
        Tok::Ipv4 { .. } => "IPv4 adresi",
        Tok::Ipv6 { .. } => "IPv6 adresi",
        Tok::Bytes(_) => "bayt dizisi",
        _ => "kelime",
    }
}
