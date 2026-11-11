//! `Dissector` trait'i ve katman katman ayrıştıran `Registry`.

use std::ops::Range;

use crate::field::{Field, FieldDef, FieldType, FieldValue, Layer};
use crate::RawPacket;

/// En fazla protokol katmanı (frame ve data hariç).
const MAX_LAYERS: usize = 16;

/// Sonraki katmanın nasıl seçileceğine dair ipucu.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NextHint {
    EtherType(u16),
    IpProto(u8),
    UdpPort { src: u16, dst: u16 },
    TcpPort { src: u16, dst: u16 },
    Named(&'static str),
    None,
}

/// Paket başına paylaşılan ayrıştırma durumu. Üst katmanlar alt katmanların
/// yazdığı `src`/`dst`/`info` değerlerinin üzerine yazar.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Ctx {
    /// Kablodaki uzunluk.
    pub frame_len: usize,
    /// Yakalanan uzunluk.
    pub cap_len: usize,
    pub src: Option<String>,
    pub dst: Option<String>,
    pub info: Option<String>,
    /// Ağ katmanının başlığa göre bildirdiği L4 uzunluğu (yakalama kırpılsa da doğru).
    pub l4_len: Option<usize>,
}

/// Bir dissector çağrısının sonucu.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DissectResult {
    pub layer: Layer,
    pub next: NextHint,
    /// Yükün, `dissect`'e verilen dilime göre (yerel) aralığı.
    pub payload: Range<usize>,
}

impl DissectResult {
    #[must_use]
    pub fn new(layer: Layer, next: NextHint, payload: Range<usize>) -> Self {
        Self {
            layer,
            next,
            payload,
        }
    }

    /// Yükü olmayan son katman.
    #[must_use]
    pub fn last(layer: Layer) -> Self {
        Self::new(layer, NextHint::None, 0..0)
    }
}

/// Protokol ayrıştırıcısı. Uygulamalar asla panic etmemeli.
pub trait Dissector: Send + Sync {
    /// Filtre adı (ör. `tcp`).
    fn name(&self) -> &'static str;
    /// Özet tablosundaki protokol adı (ör. `TCP`).
    fn display_name(&self) -> &'static str {
        self.name()
    }
    fn can_dissect(&self, ctx: &Ctx, hint: &NextHint, data: &[u8]) -> bool;
    /// `data` bu katmandan itibaren kalan bayttır; `base_offset` onun frame'deki mutlak ofseti.
    fn dissect(&self, ctx: &mut Ctx, data: &[u8], base_offset: usize) -> DissectResult;
    /// Bu protokolün tüm alanları (filtre otomatik tamamlama için).
    fn fields(&self) -> &'static [FieldDef];
}

/// Paket listesinde gösterilen tek satırlık özet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Summary {
    pub src: String,
    pub dst: String,
    /// En üst protokolün görünen adı.
    pub protocol: &'static str,
    pub info: String,
    /// Kablodaki uzunluk.
    pub len: u32,
}

/// Bir paketin tam ayrıştırması.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dissection {
    /// İlk katman her zaman `frame`.
    pub layers: Vec<Layer>,
    pub summary: Summary,
}

impl Dissection {
    /// Ada göre ilk alan.
    #[must_use]
    pub fn find(&self, name: &str) -> Option<&Field> {
        self.layers.iter().find_map(|l| l.find(name))
    }

    #[must_use]
    pub fn layer(&self, protocol: &str) -> Option<&Layer> {
        self.layers.iter().find(|l| l.protocol == protocol)
    }

    #[must_use]
    pub fn protocols(&self) -> Vec<&'static str> {
        self.layers.iter().map(|l| l.protocol).collect()
    }
}

const FRAME_FIELDS: &[FieldDef] = &[
    FieldDef::new("frame", FieldType::None, "Frame"),
    FieldDef::new("frame.number", FieldType::U64, "Frame number"),
    FieldDef::new("frame.time", FieldType::Time, "Arrival time"),
    FieldDef::new("frame.len", FieldType::U32, "Frame length on the wire"),
    FieldDef::new("frame.cap_len", FieldType::U32, "Captured length"),
];

const DATA_FIELDS: &[FieldDef] = &[
    FieldDef::new("data", FieldType::None, "Data"),
    FieldDef::new("data.data", FieldType::Bytes, "Data bytes"),
    FieldDef::new("data.len", FieldType::U32, "Data length"),
];

/// Kayıtlı dissector'lar. `Registry::default()` tüm yerleşik protokolleri içerir.
pub struct Registry {
    dissectors: Vec<Box<dyn Dissector>>,
    link: NextHint,
}

impl Default for Registry {
    fn default() -> Self {
        Self::new(crate::proto::builtin())
    }
}

impl Registry {
    /// Bağlantı katmanı Ethernet kabul edilir.
    #[must_use]
    pub fn new(dissectors: Vec<Box<dyn Dissector>>) -> Self {
        Self {
            dissectors,
            link: NextHint::Named("eth"),
        }
    }

    pub fn register(&mut self, d: Box<dyn Dissector>) {
        self.dissectors.push(d);
    }

    /// frame + data + tüm dissector alanları.
    #[must_use]
    pub fn all_fields(&self) -> Vec<FieldDef> {
        let mut v: Vec<FieldDef> = FRAME_FIELDS.to_vec();
        for d in &self.dissectors {
            v.extend_from_slice(d.fields());
        }
        v.extend_from_slice(DATA_FIELDS);
        v
    }

    #[must_use]
    pub fn dissect(&self, pkt: &RawPacket) -> Dissection {
        self.dissect_numbered(pkt, None)
    }

    /// `frame.number` alanını da üretir.
    #[must_use]
    pub fn dissect_numbered(&self, pkt: &RawPacket, number: Option<u64>) -> Dissection {
        let data = pkt.data.as_slice();
        let cap_len = u32::try_from(data.len()).unwrap_or(u32::MAX);
        let mut layers = vec![frame_layer(pkt, number, cap_len)];
        let mut ctx = Ctx {
            frame_len: usize::try_from(pkt.orig_len).unwrap_or(usize::MAX),
            cap_len: data.len(),
            ..Ctx::default()
        };
        let mut protocol = "frame";
        let mut hint = self.link;
        let (mut start, mut end) = (0usize, data.len());

        for _ in 0..MAX_LAYERS {
            let Some(slice) = data.get(start..end) else {
                break;
            };
            if slice.is_empty() {
                break;
            }
            let Some(d) = self
                .dissectors
                .iter()
                .find(|d| d.can_dissect(&ctx, &hint, slice))
            else {
                break;
            };
            let r = d.dissect(&mut ctx, slice, start);
            protocol = d.display_name();
            layers.push(r.layer);
            hint = r.next;
            let ps = r.payload.start.min(slice.len());
            let pe = r.payload.end.clamp(ps, slice.len());
            end = start + pe;
            start += ps;
        }

        if let Some(rest) = data.get(start..end).filter(|s| !s.is_empty()) {
            layers.push(data_layer(start, rest.len()));
        }

        let summary = Summary {
            src: ctx.src.unwrap_or_default(),
            dst: ctx.dst.unwrap_or_default(),
            protocol,
            info: ctx.info.unwrap_or_default(),
            len: pkt.orig_len,
        };
        Dissection { layers, summary }
    }
}

fn frame_layer(pkt: &RawPacket, number: Option<u64>, cap_len: u32) -> Layer {
    let mut l = Layer::new(
        "frame",
        format!(
            "Frame{}: {} bytes on wire, {cap_len} bytes captured",
            number.map(|n| format!(" {n}")).unwrap_or_default(),
            pkt.orig_len
        ),
        0,
        pkt.data.len(),
    );
    if let Some(n) = number {
        l.push(Field::opt(
            "frame.number",
            "Frame Number",
            Some(FieldValue::U64(n)),
            0,
            0,
        ));
    }
    l.push(Field::opt(
        "frame.time",
        "Arrival Time",
        Some(FieldValue::Time(pkt.ts)),
        0,
        0,
    ));
    l.push(Field::opt(
        "frame.len",
        "Frame Length",
        Some(FieldValue::U32(pkt.orig_len)),
        0,
        0,
    ));
    l.push(Field::opt(
        "frame.cap_len",
        "Capture Length",
        Some(FieldValue::U32(cap_len)),
        0,
        0,
    ));
    l
}

fn data_layer(offset: usize, len: usize) -> Layer {
    let mut l = Layer::new("data", format!("Data ({len} bytes)"), offset, len);
    l.push(Field::opt(
        "data.data",
        "Data",
        Some(FieldValue::Bytes { offset, len }),
        offset,
        len,
    ));
    l.push(Field::opt(
        "data.len",
        "Length",
        Some(FieldValue::U32(u32::try_from(len).unwrap_or(u32::MAX))),
        offset,
        0,
    ));
    l
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{dissect, pkt, sweep};

    #[test]
    fn empty_and_garbage() {
        let d = Registry::default().dissect(&pkt(vec![]));
        assert_eq!(d.protocols(), ["frame"]);
        let d = dissect("0102");
        assert_eq!(d.protocols(), ["frame", "eth"]);
        assert!(d.layers[1].is_malformed());
        sweep("ffffffffffff0000000000000800ff");
    }

    #[test]
    fn frame_fields() {
        let d = Registry::default().dissect_numbered(&pkt(vec![0; 20]), Some(7));
        assert_eq!(d.find("frame.number").unwrap().value, FieldValue::U64(7));
        assert_eq!(d.find("frame.len").unwrap().value, FieldValue::U32(20));
        assert_eq!(d.find("frame.cap_len").unwrap().value, FieldValue::U32(20));
        assert!(d.find("frame.time").is_some());
    }

    #[test]
    fn all_fields_unique_and_complete() {
        let f = Registry::default().all_fields();
        let mut names: Vec<_> = f.iter().map(|d| d.name).collect();
        names.sort_unstable();
        let n = names.len();
        names.dedup();
        assert_eq!(n, names.len(), "yinelenen alan adı");
        for want in [
            "frame.len",
            "eth.src",
            "vlan.id",
            "arp.opcode",
            "ip.src",
            "ip.addr",
            "ipv6.nxt",
            "icmp.type",
            "icmpv6.type",
            "tcp.port",
            "tcp.flags.syn",
            "udp.port",
            "data.len",
            "dns.qry.name",
            "dns.a",
            "mdns",
            "dhcp.option.dhcp",
            "http.request.method",
            "tls.handshake.extensions_server_name",
            "quic.dcid",
            "ssh.kex_algorithms",
            "mqtt.topic",
            "ntp.flags.mode",
        ] {
            assert!(names.contains(&want), "{want} yok");
        }
        let port = f.iter().find(|d| d.name == "tcp.port").unwrap();
        assert_eq!(port.alias_of, ["tcp.srcport", "tcp.dstport"]);
    }

    #[test]
    fn layer_limit() {
        // 20 iç içe VLAN etiketi: 16 katmanda durur, kalanı data olur.
        let mut h = String::from("020000000002020000000001");
        for _ in 0..20 {
            h.push_str("81000001");
        }
        h.push_str("0800");
        let d = dissect(&h);
        assert_eq!(d.layers.len(), 1 + 16 + 1);
        assert_eq!(d.layers.last().unwrap().protocol, "data");
    }
}
