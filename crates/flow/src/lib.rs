//! pakiz-flow: TCP/UDP akış takibi, TCP analizi ve yeniden birleştirme.
//!
//! - [`FlowKey`]: yönsüz 5-tuple (küçük uç önce) + [`KeyDir`] yön bilgisi.
//! - [`FlowTable::process`]: paketi akışa bağlar, TCP analiz bayraklarını,
//!   göreli seq/ack ve ölçeklenmiş pencereyi döner.
//! - [`Reassembler`]: yön başına sıra no ile yeniden birleştirme
//!   (ilk-gelen-kazanır örtüşme politikası).
//! - [`Stream`]: Follow Stream görünümü ([`Stream::chunks`]) ve uygulama
//!   katmanı için birleşik bayt ([`Stream::data`]).
//! - [`FlowTable::conversations`]: her iki protokol için konuşma özeti.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::assert_is_empty))]

mod key;
mod reassembly;
mod stream;
mod table;

pub use key::{Dir, FlowKey, KeyDir, Proto};
pub use reassembly::{Delivery, Reassembler};
pub use stream::{render_ascii, render_hex, render_raw, Chunk, Marker, Stream, StreamId};
pub use table::{Config, Conversation, FlowTable, PacketAnalysis, TcpAnalysis, TcpInfo, TcpState};

/// Kütüphane hataları.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FlowError {
    /// Geçersiz yapılandırma değeri.
    #[error("geçersiz yapılandırma: {0}")]
    InvalidConfig(&'static str),
}

/// `usize` → `u64` (64-bit dışı platformlarda doygun).
pub(crate) fn u64_of(n: usize) -> u64 {
    u64::try_from(n).unwrap_or(u64::MAX)
}

/// `u64` → `usize` (doygun).
pub(crate) fn usize_of(n: u64) -> usize {
    usize::try_from(n).unwrap_or(usize::MAX)
}
