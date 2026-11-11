//! Paket başına küçük analiz özeti ([`FlowTag`]) ve display filter için
//! sentetik alanlar ([`annotate`], [`FIELDS`]).
//!
//! Akış analizi durumludur (önceki paketlere bağlıdır); paket yeniden
//! ayrıştırıldığında yeniden hesaplanamaz. Bu yüzden ilk geçişte üretilen
//! [`FlowTag`] saklanır ve her ayrıştırmadan sonra [`annotate`] ile alan
//! ağacına eklenir.

use pakiz_dissect::{Dissection, Field, FieldDef, FieldType, FieldValue};

use crate::{Dir, PacketAnalysis, Proto, StreamId, TcpAnalysis};

/// TCP analiz bayrakları bit kümesi.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct AnalysisFlags(u16);

impl AnalysisFlags {
    pub const RETRANSMISSION: Self = Self(1);
    pub const FAST_RETRANSMISSION: Self = Self(1 << 1);
    pub const SPURIOUS_RETRANSMISSION: Self = Self(1 << 2);
    pub const OUT_OF_ORDER: Self = Self(1 << 3);
    pub const DUPLICATE_ACK: Self = Self(1 << 4);
    pub const ZERO_WINDOW: Self = Self(1 << 5);
    pub const ZERO_WINDOW_PROBE: Self = Self(1 << 6);
    pub const WINDOW_FULL: Self = Self(1 << 7);
    pub const KEEP_ALIVE: Self = Self(1 << 8);
    pub const LOST_SEGMENT: Self = Self(1 << 9);
    pub const ACKED_UNSEEN: Self = Self(1 << 10);
    /// RST bayrağı (uzman uyarısı sayılmaz; yalnızca renklendirme için).
    pub const RST: Self = Self(1 << 11);

    /// Analiz listesinden bit kümesi. Hızlı/sahte yeniden iletim
    /// `RETRANSMISSION` bitini de açar (Wireshark gibi).
    #[must_use]
    pub fn from_analysis(a: &[TcpAnalysis]) -> Self {
        let mut f = Self::default();
        for x in a {
            f.0 |= match x {
                TcpAnalysis::Retransmission => Self::RETRANSMISSION.0,
                TcpAnalysis::FastRetransmission => {
                    Self::FAST_RETRANSMISSION.0 | Self::RETRANSMISSION.0
                }
                TcpAnalysis::SpuriousRetransmission => {
                    Self::SPURIOUS_RETRANSMISSION.0 | Self::RETRANSMISSION.0
                }
                TcpAnalysis::OutOfOrder => Self::OUT_OF_ORDER.0,
                TcpAnalysis::DuplicateAck(_) => Self::DUPLICATE_ACK.0,
                TcpAnalysis::ZeroWindow => Self::ZERO_WINDOW.0,
                TcpAnalysis::ZeroWindowProbe => Self::ZERO_WINDOW_PROBE.0,
                TcpAnalysis::WindowFull => Self::WINDOW_FULL.0,
                TcpAnalysis::Rst => Self::RST.0,
                TcpAnalysis::KeepAlive => Self::KEEP_ALIVE.0,
                TcpAnalysis::PreviousSegmentNotCaptured => Self::LOST_SEGMENT.0,
                TcpAnalysis::AckedUnseenSegment => Self::ACKED_UNSEEN.0,
            };
        }
        f
    }

    #[must_use]
    pub fn bits(self) -> u16 {
        self.0
    }

    #[must_use]
    pub fn contains(self, o: Self) -> bool {
        self.0 & o.0 == o.0
    }

    #[must_use]
    pub fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// RST dışında bir uzman uyarısı var mı (`tcp.analysis.flags`).
    #[must_use]
    pub fn has_warning(self) -> bool {
        self.0 & !Self::RST.0 != 0
    }

    /// Paket listesi etiketleri, ör. `TCP Retransmission`.
    pub fn labels(self) -> impl Iterator<Item = &'static str> {
        let specific_retx = self.contains(Self::FAST_RETRANSMISSION)
            || self.contains(Self::SPURIOUS_RETRANSMISSION);
        FLAG_INFO
            .iter()
            .filter(move |(b, ..)| self.contains(*b))
            .filter(move |(b, ..)| !(specific_retx && *b == Self::RETRANSMISSION))
            .map(|(_, _, label)| *label)
    }

    /// Bilgi sütununun başına eklenen metin: `[TCP Retransmission] ` (boş olabilir).
    #[must_use]
    pub fn info_prefix(self) -> String {
        let mut s = String::new();
        for l in self.labels() {
            s.push('[');
            s.push_str(l);
            s.push_str("] ");
        }
        s
    }
}

/// (bit, filtre alanı, etiket).
const FLAG_INFO: &[(AnalysisFlags, &str, &str)] = &[
    (
        AnalysisFlags::RETRANSMISSION,
        "tcp.analysis.retransmission",
        "TCP Retransmission",
    ),
    (
        AnalysisFlags::FAST_RETRANSMISSION,
        "tcp.analysis.fast_retransmission",
        "TCP Fast Retransmission",
    ),
    (
        AnalysisFlags::SPURIOUS_RETRANSMISSION,
        "tcp.analysis.spurious_retransmission",
        "TCP Spurious Retransmission",
    ),
    (
        AnalysisFlags::OUT_OF_ORDER,
        "tcp.analysis.out_of_order",
        "TCP Out-Of-Order",
    ),
    (
        AnalysisFlags::DUPLICATE_ACK,
        "tcp.analysis.duplicate_ack",
        "TCP Dup ACK",
    ),
    (
        AnalysisFlags::ZERO_WINDOW,
        "tcp.analysis.zero_window",
        "TCP ZeroWindow",
    ),
    (
        AnalysisFlags::ZERO_WINDOW_PROBE,
        "tcp.analysis.zero_window_probe",
        "TCP ZeroWindowProbe",
    ),
    (
        AnalysisFlags::WINDOW_FULL,
        "tcp.analysis.window_full",
        "TCP Window Full",
    ),
    (
        AnalysisFlags::KEEP_ALIVE,
        "tcp.analysis.keep_alive",
        "TCP Keep-Alive",
    ),
    (
        AnalysisFlags::LOST_SEGMENT,
        "tcp.analysis.lost_segment",
        "TCP Previous segment not captured",
    ),
    (
        AnalysisFlags::ACKED_UNSEEN,
        "tcp.analysis.ack_lost_segment",
        "TCP ACKed unseen segment",
    ),
];

/// Saklanan paket başı akış özeti (~24 bayt).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FlowTag {
    pub stream: StreamId,
    pub dir: Dir,
    pub flags: AnalysisFlags,
    /// Göreli sıra no (yalnızca TCP).
    pub rel_seq: Option<u32>,
    /// Göreli ACK (yalnızca TCP, ACK varsa).
    pub rel_ack: Option<u32>,
}

impl From<&PacketAnalysis> for FlowTag {
    fn from(a: &PacketAnalysis) -> Self {
        let tcp = a.tcp.as_ref();
        Self {
            stream: a.stream,
            dir: a.dir,
            flags: tcp.map_or_else(AnalysisFlags::default, |t| {
                AnalysisFlags::from_analysis(&t.analysis)
            }),
            rel_seq: tcp.map(|t| t.rel_seq),
            rel_ack: tcp.and_then(|t| t.rel_ack),
        }
    }
}

/// Filtre kataloğu ve otomatik tamamlama için sentetik alanlar.
pub const FIELDS: &[FieldDef] = &[
    FieldDef::new("tcp.stream", FieldType::U32, "TCP stream index"),
    FieldDef::new("udp.stream", FieldType::U32, "UDP stream index"),
    FieldDef::new("tcp.seq_rel", FieldType::U32, "Relative sequence number"),
    FieldDef::new(
        "tcp.ack_rel",
        FieldType::U32,
        "Relative acknowledgment number",
    ),
    FieldDef::new("tcp.analysis", FieldType::None, "SEQ/ACK analysis"),
    FieldDef::new(
        "tcp.analysis.flags",
        FieldType::None,
        "TCP analysis flags (any expert warning)",
    ),
    FieldDef::new(
        "tcp.analysis.retransmission",
        FieldType::None,
        "Retransmission (incl. fast/spurious)",
    ),
    FieldDef::new(
        "tcp.analysis.fast_retransmission",
        FieldType::None,
        "Fast retransmission",
    ),
    FieldDef::new(
        "tcp.analysis.spurious_retransmission",
        FieldType::None,
        "Spurious retransmission",
    ),
    FieldDef::new(
        "tcp.analysis.out_of_order",
        FieldType::None,
        "Out-of-order segment",
    ),
    FieldDef::new(
        "tcp.analysis.duplicate_ack",
        FieldType::None,
        "Duplicate ACK",
    ),
    FieldDef::new("tcp.analysis.zero_window", FieldType::None, "Zero window"),
    FieldDef::new(
        "tcp.analysis.zero_window_probe",
        FieldType::None,
        "Zero window probe",
    ),
    FieldDef::new("tcp.analysis.window_full", FieldType::None, "Window full"),
    FieldDef::new("tcp.analysis.keep_alive", FieldType::None, "Keep-alive"),
    FieldDef::new(
        "tcp.analysis.lost_segment",
        FieldType::None,
        "Previous segment not captured",
    ),
    FieldDef::new(
        "tcp.analysis.ack_lost_segment",
        FieldType::None,
        "ACKed unseen segment",
    ),
];

/// Akış özetini TCP/UDP katmanına sentetik alanlar olarak ekler:
/// `tcp.stream`/`udp.stream`, TCP'de ayrıca `[SEQ/ACK analysis]` düğümü
/// (`tcp.analysis`, göreli seq/ack, `tcp.analysis.flags` ve bayrak alanları).
/// Sentetik alanların uzunluğu 0'dır (hex vurgusu yok).
pub fn annotate(d: &mut Dissection, tag: &FlowTag) {
    let proto = match tag.stream.proto {
        Proto::Tcp => "tcp",
        Proto::Udp => "udp",
    };
    let Some(layer) = d.layers.iter_mut().find(|l| l.protocol == proto) else {
        return;
    };
    let off = layer.offset;
    let idx = tag.stream.index;
    layer.push(Field::new(
        if proto == "tcp" {
            "tcp.stream"
        } else {
            "udp.stream"
        },
        format!("[Stream index: {idx}]"),
        FieldValue::U32(idx),
        off,
        0,
    ));
    if tag.stream.proto != Proto::Tcp {
        return;
    }
    let mut seqack = Field::new(
        "tcp.analysis",
        "[SEQ/ACK analysis]",
        FieldValue::None,
        off,
        0,
    );
    if let Some(s) = tag.rel_seq {
        seqack.push(Field::new(
            "tcp.seq_rel",
            format!("[Relative sequence number: {s}]"),
            FieldValue::U32(s),
            off,
            0,
        ));
    }
    if let Some(a) = tag.rel_ack {
        seqack.push(Field::new(
            "tcp.ack_rel",
            format!("[Relative acknowledgment number: {a}]"),
            FieldValue::U32(a),
            off,
            0,
        ));
    }
    if tag.flags.has_warning() {
        let mut flags = Field::new(
            "tcp.analysis.flags",
            "[TCP Analysis Flags]",
            FieldValue::None,
            off,
            0,
        );
        for (bit, name, label) in FLAG_INFO {
            if tag.flags.contains(*bit) {
                flags.push(Field::new(
                    name,
                    format!("[Expert Info: {label}]"),
                    FieldValue::None,
                    off,
                    0,
                ));
            }
        }
        seqack.push(flags);
    }
    layer.push(seqack);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_and_labels() {
        let f = AnalysisFlags::from_analysis(&[TcpAnalysis::FastRetransmission]);
        assert!(f.contains(AnalysisFlags::RETRANSMISSION));
        assert_eq!(f.info_prefix(), "[TCP Fast Retransmission] ");
        let f = AnalysisFlags::from_analysis(&[TcpAnalysis::Rst]);
        assert!(!f.has_warning() && f.info_prefix().is_empty());
        let f =
            AnalysisFlags::from_analysis(&[TcpAnalysis::DuplicateAck(2), TcpAnalysis::ZeroWindow]);
        assert_eq!(f.info_prefix(), "[TCP Dup ACK] [TCP ZeroWindow] ");
        // Her bayrağın kataloğa girmiş bir alanı var.
        for (_, name, _) in FLAG_INFO {
            assert!(FIELDS.iter().any(|d| d.name == *name), "{name}");
        }
    }
}
