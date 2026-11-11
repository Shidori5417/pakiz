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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn permission_error_suggests_setcap() {
        for errno in [libc::EPERM, libc::EACCES] {
            let e = from_io("socket(AF_PACKET)", io::Error::from_raw_os_error(errno));
            assert!(matches!(e, CaptureError::Permission { .. }));
            let m = e.to_string();
            assert!(m.starts_with("socket(AF_PACKET): yetki yok."), "{m}");
            assert!(
                m.contains("CAP_NET_RAW")
                    && m.contains("sudo setcap cap_net_raw,cap_net_admin=eip /"),
                "{m}"
            );
        }
        let e = from_io("bind", io::Error::from_raw_os_error(libc::ENODEV));
        assert!(matches!(e, CaptureError::Io { op: "bind", .. }));
        assert!(e.to_string().starts_with("bind: "));
    }
}
