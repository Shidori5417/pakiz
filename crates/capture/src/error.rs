use std::io;

/// Yakalama katmanı hataları.
#[derive(Debug, thiserror::Error)]
pub enum CaptureError {
    /// Raw socket için yetki yok (EPERM/EACCES).
    #[error(
        "{op}: yetki yok. CAP_NET_RAW/CAP_NET_ADMIN gerekli: sudo setcap cap_net_raw,cap_net_admin=eip {exe}"
    )]
    Permission { op: &'static str, exe: String },
    /// Arayüz bulunamadı.
    #[error("arayüz bulunamadı: {0}")]
    NoSuchInterface(String),
    /// Diğer sistem çağrısı hataları.
    #[error("{op}: {source}")]
    Io {
        op: &'static str,
        #[source]
        source: io::Error,
    },
    /// Yakalama thread'i panikledi.
    #[error("yakalama thread'i beklenmedik şekilde sonlandı")]
    ThreadPanicked,
}

pub type Result<T> = std::result::Result<T, CaptureError>;

/// `errno`'yu okuyup uygun hataya çevirir.
pub(crate) fn last_os_error(op: &'static str) -> CaptureError {
    from_io(op, io::Error::last_os_error())
}

pub(crate) fn from_io(op: &'static str, source: io::Error) -> CaptureError {
    match source.raw_os_error() {
        Some(libc::EPERM | libc::EACCES) => CaptureError::Permission {
            op,
            exe: std::env::current_exe()
                .map_or_else(|_| "<binary yolu>".to_owned(), |p| p.display().to_string()),
        },
        _ => CaptureError::Io { op, source },
    }
}
