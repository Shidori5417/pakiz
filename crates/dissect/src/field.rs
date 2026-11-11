//! Alan ağacı tipleri.

use std::borrow::Cow;
use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::{SystemTime, UNIX_EPOCH};

/// Bir alanın çözülmüş değeri.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FieldValue {
    U8(u8),
    U16(u16),
    U32(u32),
    U64(u64),
    Bool(bool),
    /// Ham bayt aralığı (frame'e göre mutlak ofset).
    Bytes {
        offset: usize,
        len: usize,
    },
    Str(Cow<'static, str>),
    Ipv4(Ipv4Addr),
    Ipv6(Ipv6Addr),
    Mac([u8; 6]),
    Time(SystemTime),
    /// Değersiz alan (protokol kökü, bayrak grubu vb.).
    None,
}

impl FieldValue {
    /// Sayısal/bool değeri `u64` olarak verir.
    #[must_use]
    pub fn as_u64(&self) -> Option<u64> {
        match *self {
            Self::U8(v) => Some(u64::from(v)),
            Self::U16(v) => Some(u64::from(v)),
            Self::U32(v) => Some(u64::from(v)),
            Self::U64(v) => Some(v),
            Self::Bool(v) => Some(u64::from(v)),
            _ => None,
        }
    }
}

/// `aa:bb:cc:dd:ee:ff` biçimi.
#[must_use]
pub fn fmt_mac(m: &[u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        m[0], m[1], m[2], m[3], m[4], m[5]
    )
}

impl fmt::Display for FieldValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::U8(v) => write!(f, "{v}"),
            Self::U16(v) => write!(f, "{v}"),
            Self::U32(v) => write!(f, "{v}"),
            Self::U64(v) => write!(f, "{v}"),
            Self::Bool(v) => f.write_str(if *v { "Set" } else { "Not set" }),
            Self::Bytes { len, .. } => write!(f, "{len} bytes"),
            Self::Str(s) => f.write_str(s),
            Self::Ipv4(a) => write!(f, "{a}"),
            Self::Ipv6(a) => write!(f, "{a}"),
            Self::Mac(m) => f.write_str(&fmt_mac(m)),
            Self::Time(t) => match t.duration_since(UNIX_EPOCH) {
                Ok(d) => write!(f, "{}.{:09}", d.as_secs(), d.subsec_nanos()),
                Err(_) => f.write_str("<epoch öncesi>"),
            },
            Self::None => Ok(()),
        }
    }
}

/// Filtre/otomatik tamamlama için alan tipi.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldType {
    U8,
    U16,
    U32,
    U64,
    Bool,
    Bytes,
    Str,
    Ipv4,
    Ipv6,
    Mac,
    Time,
    /// Protokol veya değersiz grup alanı (yalnızca varlık sınanır).
    None,
}

/// Statik alan tanımı.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FieldDef {
    pub name: &'static str,
    pub ty: FieldType,
    pub desc: &'static str,
    /// Sanal alan ise eşleştiği gerçek alanlar (ör. `tcp.port` → srcport/dstport).
    /// Bu alanlar ağaçta üretilmez; filter crate "herhangi biri" olarak değerlendirir.
    pub alias_of: &'static [&'static str],
}

impl FieldDef {
    #[must_use]
    pub const fn new(name: &'static str, ty: FieldType, desc: &'static str) -> Self {
        Self {
            name,
            ty,
            desc,
            alias_of: &[],
        }
    }

    #[must_use]
    pub const fn alias(
        name: &'static str,
        ty: FieldType,
        desc: &'static str,
        alias_of: &'static [&'static str],
    ) -> Self {
        Self {
            name,
            ty,
            desc,
            alias_of,
        }
    }
}

/// Alan ağacı düğümü.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Field {
    /// Tam filtre adı (ör. `ip.src`).
    pub name: &'static str,
    /// Görünen satır (ör. `Source Address: 10.0.0.1`).
    pub label: Cow<'static, str>,
    pub value: FieldValue,
    /// Frame'e göre mutlak ofset.
    pub offset: usize,
    pub len: usize,
    pub children: Vec<Field>,
    pub malformed: bool,
}

impl Field {
    #[must_use]
    pub fn new(
        name: &'static str,
        label: impl Into<Cow<'static, str>>,
        value: FieldValue,
        offset: usize,
        len: usize,
    ) -> Self {
        Self {
            name,
            label: label.into(),
            value,
            offset,
            len,
            children: Vec::new(),
            malformed: false,
        }
    }

    /// Değer okunabildiyse `"{title}: {değer}"`, okunamadıysa malformed alan.
    #[must_use]
    pub fn opt(
        name: &'static str,
        title: &str,
        value: Option<FieldValue>,
        offset: usize,
        len: usize,
    ) -> Self {
        match value {
            Some(v) => Self::new(name, format!("{title}: {v}"), v, offset, len),
            None => Self::new(
                name,
                format!("{title}: [eksik veri]"),
                FieldValue::None,
                offset,
                len,
            )
            .malformed(),
        }
    }

    #[must_use]
    pub fn malformed(mut self) -> Self {
        self.malformed = true;
        self
    }

    /// Değer varsa etiketi değiştirir (malformed alan etiketini korur).
    #[must_use]
    pub fn relabel(mut self, label: impl Into<Cow<'static, str>>) -> Self {
        if !self.malformed {
            self.label = label.into();
        }
        self
    }

    #[must_use]
    pub fn with_children(mut self, children: Vec<Field>) -> Self {
        self.children = children;
        self
    }

    pub fn push(&mut self, f: Field) {
        self.children.push(f);
    }

    /// Bu düğüm veya alt ağaçta ada göre ilk alan (önce derinlik).
    #[must_use]
    pub fn find(&self, name: &str) -> Option<&Field> {
        if self.name == name {
            return Some(self);
        }
        self.children.iter().find_map(|c| c.find(name))
    }

    /// Alt ağaçta herhangi bir malformed alan var mı?
    #[must_use]
    pub fn is_malformed(&self) -> bool {
        self.malformed || self.children.iter().any(Field::is_malformed)
    }
}

/// Tek bir protokol katmanı.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Layer {
    /// Protokol filtre adı (ör. `tcp`).
    pub protocol: &'static str,
    /// Kök alan (adı = `protocol`).
    pub fields: Field,
    pub offset: usize,
    pub len: usize,
}

impl Layer {
    #[must_use]
    pub fn new(
        protocol: &'static str,
        label: impl Into<Cow<'static, str>>,
        offset: usize,
        len: usize,
    ) -> Self {
        Self {
            protocol,
            fields: Field::new(protocol, label, FieldValue::None, offset, len),
            offset,
            len,
        }
    }

    pub fn push(&mut self, f: Field) {
        self.fields.push(f);
    }

    pub fn set_label(&mut self, label: impl Into<Cow<'static, str>>) {
        self.fields.label = label.into();
    }

    #[must_use]
    pub fn find(&self, name: &str) -> Option<&Field> {
        self.fields.find(name)
    }

    #[must_use]
    pub fn is_malformed(&self) -> bool {
        self.fields.is_malformed()
    }
}
