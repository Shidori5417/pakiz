//! HTTP/1.x (tek segment; yeniden birleştirme flow katmanında).

use super::util::{bytes_field, find, lossy, str_field, tcp_port};
use crate::{
    Ctx, DissectResult, Dissector, Field, FieldDef, FieldType as T, FieldValue as V, Layer,
    NextHint,
};

pub struct Http;

const PORTS: &[u16] = &[80, 8080, 8000];
const METHODS: &[&str] = &[
    "GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "CONNECT", "TRACE",
];

const FIELDS: &[FieldDef] = &[
    FieldDef::new("http", T::None, "Hypertext Transfer Protocol"),
    FieldDef::new("http.request", T::Bool, "Request"),
    FieldDef::new("http.response", T::Bool, "Response"),
    FieldDef::new("http.request.method", T::Str, "Request method"),
    FieldDef::new("http.request.uri", T::Str, "Request URI"),
    FieldDef::new("http.request.version", T::Str, "Request version"),
    FieldDef::new("http.response.version", T::Str, "Response version"),
    FieldDef::new("http.response.code", T::U16, "Status code"),
    FieldDef::new("http.response.phrase", T::Str, "Response phrase"),
    FieldDef::new("http.request.line", T::Str, "Request header line"),
    FieldDef::new("http.response.line", T::Str, "Response header line"),
    FieldDef::new("http.host", T::Str, "Host"),
    FieldDef::new("http.user_agent", T::Str, "User-Agent"),
    FieldDef::new("http.content_type", T::Str, "Content-Type"),
    FieldDef::new("http.content_length", T::U64, "Content-Length"),
    FieldDef::new("http.server", T::Str, "Server"),
    FieldDef::new("http.connection", T::Str, "Connection"),
    FieldDef::new("http.accept", T::Str, "Accept"),
    FieldDef::new("http.referer", T::Str, "Referer"),
    FieldDef::new("http.location", T::Str, "Location"),
    FieldDef::new("http.cookie", T::Str, "Cookie"),
    FieldDef::new("http.set_cookie", T::Str, "Set-Cookie"),
    FieldDef::new("http.transfer_encoding", T::Str, "Transfer-Encoding"),
    FieldDef::new("http.file_data", T::Bytes, "Body"),
    FieldDef::new("http.continuation", T::Bytes, "Continuation data"),
];

/// Yük bir HTTP istek/yanıt satırıyla mı başlıyor?
fn looks_like_http(data: &[u8]) -> bool {
    data.starts_with(b"HTTP/1.")
        || METHODS.iter().any(|m| {
            data.len() > m.len() && data.starts_with(m.as_bytes()) && data[m.len()] == b' '
        })
}

/// Bilinen başlık → filtre alanı.
fn header_field(name: &str) -> Option<&'static str> {
    Some(match name.to_ascii_lowercase().as_str() {
        "host" => "http.host",
        "user-agent" => "http.user_agent",
        "content-type" => "http.content_type",
        "content-length" => "http.content_length",
        "server" => "http.server",
        "connection" => "http.connection",
        "accept" => "http.accept",
        "referer" => "http.referer",
        "location" => "http.location",
        "cookie" => "http.cookie",
        "set-cookie" => "http.set_cookie",
        "transfer-encoding" => "http.transfer_encoding",
        _ => return None,
    })
}

impl Dissector for Http {
    fn name(&self) -> &'static str {
        "http"
    }
    fn display_name(&self) -> &'static str {
        "HTTP"
    }
    fn can_dissect(&self, _: &Ctx, hint: &NextHint, data: &[u8]) -> bool {
        matches!(hint, NextHint::TcpPort { .. }) && (tcp_port(hint, PORTS) || looks_like_http(data))
    }
    fn fields(&self) -> &'static [FieldDef] {
        FIELDS
    }

    fn dissect(&self, ctx: &mut Ctx, data: &[u8], base: usize) -> DissectResult {
        let mut l = Layer::new("http", "Hypertext Transfer Protocol", base, data.len());
        if !looks_like_http(data) {
            l.push(bytes_field(
                "http.continuation",
                "Continuation",
                Some(data),
                base,
                data.len(),
            ));
            ctx.info = Some("Continuation".to_owned());
            return DissectResult::last(l);
        }
        // Başlık sonu; segmentte yoksa tüm yük başlık kabul edilir (tamamlanmış satırlar).
        let hdr_end = find(data, b"\r\n\r\n").map(|i| i + 4);
        let head = &data[..hdr_end.unwrap_or(data.len())];
        let response = data.starts_with(b"HTTP/");
        let mut lines = Vec::new();
        let mut o = 0;
        while let Some(i) = find(&head[o..], b"\n") {
            lines.push((o, &head[o..=o + i]));
            o += i + 1;
        }
        let mut info = None;
        let mut content_type = None;
        for (n, (off, raw)) in lines.into_iter().enumerate() {
            let text = raw.strip_suffix(b"\n").unwrap_or(raw);
            let text = text.strip_suffix(b"\r").unwrap_or(text);
            let s = lossy(text);
            let abs = base + off;
            if s.is_empty() {
                continue;
            }
            if n == 0 {
                let mut parts = s.splitn(3, ' ');
                let (a, b, c) = (parts.next(), parts.next(), parts.next());
                let mut f = Field::new(
                    if response {
                        "http.response"
                    } else {
                        "http.request"
                    },
                    format!("{s}\\r\\n"),
                    V::Bool(true),
                    abs,
                    raw.len(),
                );
                if response {
                    let code = b.and_then(|b| b.parse::<u16>().ok());
                    f.push(str_field(
                        "http.response.version",
                        "Response Version",
                        a.map(str::to_owned),
                        abs,
                        a.map_or(0, str::len),
                    ));
                    f.push(Field::opt(
                        "http.response.code",
                        "Status Code",
                        code.map(V::U16),
                        abs,
                        3,
                    ));
                    f.push(str_field(
                        "http.response.phrase",
                        "Response Phrase",
                        Some(c.unwrap_or("").to_owned()),
                        abs,
                        c.map_or(0, str::len),
                    ));
                    if code.is_none() {
                        f = f.malformed();
                    }
                } else {
                    f.push(str_field(
                        "http.request.method",
                        "Request Method",
                        a.map(str::to_owned),
                        abs,
                        a.map_or(0, str::len),
                    ));
                    f.push(str_field(
                        "http.request.uri",
                        "Request URI",
                        b.map(str::to_owned),
                        abs,
                        b.map_or(0, str::len),
                    ));
                    f.push(str_field(
                        "http.request.version",
                        "Request Version",
                        c.map(str::to_owned),
                        abs,
                        c.map_or(0, str::len),
                    ));
                    if !c.is_some_and(|v| v.starts_with("HTTP/")) {
                        f = f.malformed();
                    }
                }
                l.push(f);
                info = Some(s);
                continue;
            }
            let mut f = Field::new(
                if response {
                    "http.response.line"
                } else {
                    "http.request.line"
                },
                format!("{s}\\r\\n"),
                V::Str(s.clone().into()),
                abs,
                raw.len(),
            );
            if let Some((k, v)) = s.split_once(':') {
                let v = v.trim();
                if let Some(name) = header_field(k.trim()) {
                    let child = if name == "http.content_length" {
                        Field::opt(
                            name,
                            k.trim(),
                            v.parse::<u64>().ok().map(V::U64),
                            abs,
                            raw.len(),
                        )
                    } else {
                        str_field(name, k.trim(), Some(v.to_owned()), abs, raw.len())
                    };
                    if name == "http.content_type" {
                        content_type = Some(v.to_owned());
                    }
                    f.push(child);
                }
            }
            l.push(f);
        }
        if let Some(e) = hdr_end {
            if e < data.len() {
                let n = data.len() - e;
                l.push(bytes_field(
                    "http.file_data",
                    "File Data",
                    data.get(e..),
                    base + e,
                    n,
                ));
            }
        }
        let mut info = info.unwrap_or_default();
        if response {
            if let Some(ct) = content_type {
                info = format!("{info}  ({ct})");
            }
        }
        ctx.info = Some(info);
        DissectResult::last(l)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use crate::testutil::{dissect, sweep};
    use crate::FieldValue as V;

    // 192.168.1.10:51000 → 93.184.216.34:80, GET / (curl).
    pub(crate) const GET: &str = "a0b1c2d3e4f53c22fb1a2b3c0800450000721c464000400626b3c0a8010a5db8d822c73800500000000100000001501801f65ebe0000474554202f20485454502f312e310d0a486f73743a206578616d706c652e636f6d0d0a557365722d4167656e743a206375726c2f382e352e300d0a4163636570743a202a2f2a0d0a0d0a";
    // 93.184.216.34:80 → 192.168.1.10:51000, 200 OK + 5 bayt gövde.
    pub(crate) const RESP: &str = "a0b1c2d3e4f53c22fb1a2b3c0800450000791c464000400626ac5db8d822c0a8010a0050c7380000000100000001501801f6af500000485454502f312e3120323030204f4b0d0a436f6e74656e742d547970653a20746578742f68746d6c0d0a436f6e74656e742d4c656e6774683a20350d0a5365727665723a204543530d0a0d0a68656c6c6f";
    // Port 3000'de POST (içerik sezgisi).
    pub(crate) const POST: &str = "a0b1c2d3e4f53c22fb1a2b3c0800450000891c46400040069ac9c0a8010ac0a801059c400bb80000000100000001501801f6c8280000504f5354202f61706920485454502f312e310d0a486f73743a206c6f63616c686f73743a333030300d0a436f6e74656e742d547970653a206170706c69636174696f6e2f6a736f6e0d0a436f6e74656e742d4c656e6774683a20320d0a0d0a7b7d";

    #[test]
    fn request() {
        let d = dissect(GET);
        assert_eq!(d.protocols(), ["frame", "eth", "ip", "tcp", "http"]);
        assert_eq!(d.summary.protocol, "HTTP");
        assert_eq!(d.summary.info, "GET / HTTP/1.1");
        assert_eq!(d.find("http.request").unwrap().value, V::Bool(true));
        assert_eq!(
            d.find("http.request.method").unwrap().value,
            V::Str("GET".into())
        );
        assert_eq!(
            d.find("http.request.uri").unwrap().value,
            V::Str("/".into())
        );
        assert_eq!(
            d.find("http.request.version").unwrap().value,
            V::Str("HTTP/1.1".into())
        );
        assert_eq!(
            d.find("http.host").unwrap().value,
            V::Str("example.com".into())
        );
        assert_eq!(
            d.find("http.user_agent").unwrap().value,
            V::Str("curl/8.5.0".into())
        );
        assert!(!d.layer("http").unwrap().is_malformed());
    }

    #[test]
    fn response() {
        let d = dissect(RESP);
        assert_eq!(d.summary.info, "HTTP/1.1 200 OK  (text/html)");
        assert_eq!(d.find("http.response").unwrap().value, V::Bool(true));
        assert_eq!(d.find("http.response.code").unwrap().value, V::U16(200));
        assert_eq!(
            d.find("http.response.phrase").unwrap().value,
            V::Str("OK".into())
        );
        assert_eq!(
            d.find("http.content_type").unwrap().value,
            V::Str("text/html".into())
        );
        assert_eq!(d.find("http.content_length").unwrap().value, V::U64(5));
        assert_eq!(d.find("http.file_data").unwrap().len, 5);
    }

    #[test]
    fn heuristic_any_port() {
        let d = dissect(POST);
        assert_eq!(d.protocols(), ["frame", "eth", "ip", "tcp", "http"]);
        assert_eq!(d.summary.info, "POST /api HTTP/1.1");
        assert_eq!(d.find("http.content_length").unwrap().value, V::U64(2));
    }

    #[test]
    fn truncation_sweep() {
        for h in [GET, RESP, POST] {
            sweep(h);
        }
    }
}
