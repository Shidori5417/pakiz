//! Yerel soket → süreç eşleme.
//!
//! Soket tablosu önce `NETLINK_SOCK_DIAG` (`inet_diag_req_v2`) ile, olmazsa
//! `/proc/net/{tcp,tcp6,udp,udp6}` ile okunur; inode → pid eşlemesi
//! `/proc/<pid>/fd/*` bağlantılarından çıkarılır. Her şey best-effort'tur:
//! izin yoksa veya bulunamazsa `None` döner.

use std::collections::HashMap;
use std::fs;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::{Duration, Instant};

use pakiz_dissect::Dissection;

use crate::{Endpoints, Error, Transport};

/// Bir soketin sahibi süreç.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessInfo {
    pub pid: u32,
    /// `/proc/<pid>/comm`.
    pub name: String,
    pub inode: u64,
}

/// Soket tablosundaki tek kayıt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SocketEntry {
    pub proto: Transport,
    pub local: SocketAddr,
    pub remote: SocketAddr,
    pub inode: u64,
}

/// Soket tablosu kaynağı.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backend {
    /// `sock_diag`, başarısızsa /proc.
    Auto,
    /// Yalnızca `NETLINK_SOCK_DIAG`.
    SockDiag,
    /// Yalnızca `/proc/net/*`.
    Proc,
}

/// IPv4-mapped IPv6 adresini IPv4'e indirger.
fn canon(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
        IpAddr::V4(_) => ip,
    }
}

fn canon_sock(s: SocketAddr) -> SocketAddr {
    SocketAddr::new(canon(s.ip()), s.port())
}

/// Önbellekli soket → süreç çözücü.
#[derive(Debug)]
pub struct ProcessResolver {
    backend: Backend,
    min_interval: Duration,
    last_refresh: Option<Instant>,
    /// (proto, yerel, uzak) → inode.
    exact: HashMap<(Transport, SocketAddr, SocketAddr), u64>,
    /// (proto, yerel) → inode (bağlı olmayan / ilk eşleşen).
    local: HashMap<(Transport, SocketAddr), u64>,
    /// 0.0.0.0 / :: üzerinde dinleyen: (proto, port) → inode.
    wildcard: HashMap<(Transport, u16), u64>,
    procs: HashMap<u64, ProcessInfo>,
    /// Son yenilemede kullanılan kaynak (`sock_diag` mı başarılı oldu).
    used_sock_diag: bool,
}

impl Default for ProcessResolver {
    fn default() -> Self {
        Self::new(Backend::Auto)
    }
}

impl ProcessResolver {
    #[must_use]
    pub fn new(backend: Backend) -> Self {
        Self {
            backend,
            min_interval: Duration::from_secs(1),
            last_refresh: None,
            exact: HashMap::new(),
            local: HashMap::new(),
            wildcard: HashMap::new(),
            procs: HashMap::new(),
            used_sock_diag: false,
        }
    }

    /// İki tarama arasındaki en kısa süre (varsayılan 1 sn).
    #[must_use]
    pub fn with_min_interval(mut self, d: Duration) -> Self {
        self.min_interval = d;
        self
    }

    /// Son başarılı yenileme `sock_diag` ile mi yapıldı?
    #[must_use]
    pub fn used_sock_diag(&self) -> bool {
        self.used_sock_diag
    }

    /// Tabloları yeniler; son yenilemeden bu yana `min_interval` geçmediyse
    /// hiçbir şey yapmaz. Yenileme yapıldıysa `true`.
    pub fn refresh(&mut self) -> bool {
        if self
            .last_refresh
            .is_some_and(|t| t.elapsed() < self.min_interval)
        {
            return false;
        }
        self.force_refresh();
        true
    }

    /// Hız sınırı olmadan yeniler.
    pub fn force_refresh(&mut self) {
        self.last_refresh = Some(Instant::now());
        let (entries, diag) = match self.backend {
            Backend::SockDiag => (sock_diag_dump().unwrap_or_default(), true),
            Backend::Proc => (proc_net_dump(), false),
            Backend::Auto => match sock_diag_dump() {
                Ok(e) if !e.is_empty() => (e, true),
                _ => (proc_net_dump(), false),
            },
        };
        self.used_sock_diag = diag;
        self.exact.clear();
        self.local.clear();
        self.wildcard.clear();
        for e in &entries {
            if e.inode == 0 {
                continue; // TIME_WAIT vb.
            }
            let (l, r) = (canon_sock(e.local), canon_sock(e.remote));
            self.exact.insert((e.proto, l, r), e.inode);
            self.local.entry((e.proto, l)).or_insert(e.inode);
            if l.ip().is_unspecified() {
                self.wildcard.entry((e.proto, l.port())).or_insert(e.inode);
            }
        }
        self.procs = scan_proc_fds();
    }

    fn find_inode(&self, proto: Transport, local: SocketAddr, remote: SocketAddr) -> Option<u64> {
        let (l, r) = (canon_sock(local), canon_sock(remote));
        self.exact
            .get(&(proto, l, r))
            .or_else(|| self.local.get(&(proto, l)))
            .or_else(|| self.wildcard.get(&(proto, l.port())))
            .copied()
    }

    /// Önbellekten bakar; yoksa (hız sınırı içinde) yenileyip tekrar dener.
    pub fn lookup(
        &mut self,
        proto: Transport,
        local: SocketAddr,
        remote: SocketAddr,
    ) -> Option<&ProcessInfo> {
        let hit = self
            .find_inode(proto, local, remote)
            .is_some_and(|i| self.procs.contains_key(&i));
        if !hit {
            self.refresh();
        }
        let inode = self.find_inode(proto, local, remote)?;
        self.procs.get(&inode)
    }

    /// Paketin iki yönünü dener: önce kaynak yerel, sonra hedef yerel.
    pub fn lookup_packet(&mut self, d: &Dissection) -> Option<&ProcessInfo> {
        let ep = Endpoints::from_dissection(d)?;
        let (proto, ..) = ep.l4?;
        let (s, t) = (ep.src_sock()?, ep.dst_sock()?);
        let hit = |me: &Self| {
            [(s, t), (t, s)]
                .into_iter()
                .find_map(|(l, r)| me.find_inode(proto, l, r))
                .filter(|i| me.procs.contains_key(i))
        };
        let inode = if let Some(i) = hit(self) {
            i
        } else {
            self.refresh();
            hit(self)?
        };
        self.procs.get(&inode)
    }
}

// ---------------------------------------------------------------- sock_diag

const SOCK_DIAG_BY_FAMILY: u16 = 20;
const NLM_F_REQUEST: u16 = 0x1;
const NLM_F_DUMP: u16 = 0x300;
const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;
const AF_INET: u8 = 2;
const AF_INET6: u8 = 10;

/// `nlmsghdr` + `inet_diag_req_v2` isteğini bayt bayt kurar.
fn diag_request(family: u8, proto: Transport, seq: u32) -> Vec<u8> {
    let mut b = Vec::with_capacity(72);
    b.extend_from_slice(&72u32.to_ne_bytes()); // nlmsg_len
    b.extend_from_slice(&SOCK_DIAG_BY_FAMILY.to_ne_bytes());
    b.extend_from_slice(&(NLM_F_REQUEST | NLM_F_DUMP).to_ne_bytes());
    b.extend_from_slice(&seq.to_ne_bytes());
    b.extend_from_slice(&0u32.to_ne_bytes()); // pid
                                              // inet_diag_req_v2
    b.extend_from_slice(&[family, proto.ip_proto(), 0, 0]);
    b.extend_from_slice(&u32::MAX.to_ne_bytes()); // tüm durumlar
    b.resize(72, 0); // inet_diag_sockid (48 bayt) sıfır
    b
}

fn ne_u16(b: &[u8], o: usize) -> Option<u16> {
    Some(u16::from_ne_bytes(b.get(o..o + 2)?.try_into().ok()?))
}

fn ne_u32(b: &[u8], o: usize) -> Option<u32> {
    Some(u32::from_ne_bytes(b.get(o..o + 4)?.try_into().ok()?))
}

fn be_u16(b: &[u8], o: usize) -> Option<u16> {
    Some(u16::from_be_bytes(b.get(o..o + 2)?.try_into().ok()?))
}

fn diag_addr(family: u8, b: &[u8]) -> Option<IpAddr> {
    if family == AF_INET {
        let a: [u8; 4] = b.get(..4)?.try_into().ok()?;
        Some(IpAddr::V4(Ipv4Addr::from(a)))
    } else {
        let a: [u8; 16] = b.get(..16)?.try_into().ok()?;
        Some(IpAddr::V6(Ipv6Addr::from(a)))
    }
}

/// `inet_diag_msg` gövdesini ayrıştırır.
fn parse_diag_msg(proto: Transport, m: &[u8]) -> Option<SocketEntry> {
    let family = *m.first()?;
    let sport = be_u16(m, 4)?;
    let dport = be_u16(m, 6)?;
    let src = diag_addr(family, m.get(8..24)?)?;
    let dst = diag_addr(family, m.get(24..40)?)?;
    let inode = ne_u32(m, 68)?;
    Some(SocketEntry {
        proto,
        local: SocketAddr::new(src, sport),
        remote: SocketAddr::new(dst, dport),
        inode: u64::from(inode),
    })
}

/// Bir (aile, protokol) için tüm soketleri döker.
fn diag_dump_one(family: u8, proto: Transport, out: &mut Vec<SocketEntry>) -> Result<(), Error> {
    use netlink_sys::{protocols::NETLINK_SOCK_DIAG, Socket, SocketAddr as NlAddr};
    let mut sock = Socket::new(NETLINK_SOCK_DIAG)?;
    sock.bind_auto()?;
    let kernel = NlAddr::new(0, 0);
    sock.send_to(&diag_request(family, proto, 1), &kernel, 0)?;
    let mut buf: Vec<u8> = Vec::with_capacity(64 * 1024);
    loop {
        buf.clear();
        let (n, _) = sock.recv_from(&mut buf, 0)?;
        if n == 0 {
            return Err(Error::Netlink("boş cevap".into()));
        }
        let mut off = 0;
        while off + 16 <= buf.len() {
            let len = ne_u32(&buf, off).and_then(|l| usize::try_from(l).ok());
            let ty = ne_u16(&buf, off + 4);
            let (Some(len), Some(ty)) = (len, ty) else {
                break;
            };
            if len < 16 || off + len > buf.len() {
                return Err(Error::Netlink("bozuk nlmsghdr".into()));
            }
            let body = &buf[off + 16..off + len];
            match ty {
                NLMSG_DONE => return Ok(()),
                NLMSG_ERROR => {
                    let code = ne_u32(body, 0).map_or(0, u32::cast_signed);
                    if code != 0 {
                        return Err(Error::Io(std::io::Error::from_raw_os_error(-code)));
                    }
                }
                SOCK_DIAG_BY_FAMILY => out.extend(parse_diag_msg(proto, body)),
                _ => {}
            }
            off += (len + 3) & !3;
        }
    }
}

/// `NETLINK_SOCK_DIAG` ile TCP/UDP × IPv4/IPv6 soketlerini döker.
///
/// # Errors
/// Netlink soketi açılamaz veya kernel hata dönerse.
pub fn sock_diag_dump() -> Result<Vec<SocketEntry>, Error> {
    let mut out = Vec::new();
    for proto in [Transport::Tcp, Transport::Udp] {
        for fam in [AF_INET, AF_INET6] {
            diag_dump_one(fam, proto, &mut out)?;
        }
    }
    Ok(out)
}

// ------------------------------------------------------------ /proc/net/*

/// `/proc/net/tcp` hex adresi: IPv4 tek host-endian u32, IPv6 dört
/// host-endian u32 kelimesi.
fn parse_hex_addr(s: &str) -> Option<SocketAddr> {
    let (a, p) = s.split_once(':')?;
    let port = u16::from_str_radix(p, 16).ok()?;
    let word = |i: usize| -> Option<[u8; 4]> {
        Some(
            u32::from_str_radix(a.get(i * 8..i * 8 + 8)?, 16)
                .ok()?
                .to_ne_bytes(),
        )
    };
    let ip = match a.len() {
        8 => IpAddr::V4(Ipv4Addr::from(word(0)?)),
        32 => {
            let mut b = [0u8; 16];
            for i in 0..4 {
                b[i * 4..i * 4 + 4].copy_from_slice(&word(i)?);
            }
            IpAddr::V6(Ipv6Addr::from(b))
        }
        _ => return None,
    };
    Some(SocketAddr::new(ip, port))
}

/// `/proc/net/{tcp,udp}[6]` metnini ayrıştırır (başlık satırı atlanır,
/// bozuk satırlar yok sayılır).
#[must_use]
pub fn parse_proc_net(proto: Transport, text: &str) -> Vec<SocketEntry> {
    text.lines()
        .skip(1)
        .filter_map(|line| {
            let f: Vec<&str> = line.split_whitespace().collect();
            Some(SocketEntry {
                proto,
                local: parse_hex_addr(f.get(1)?)?,
                remote: parse_hex_addr(f.get(2)?)?,
                inode: f.get(9)?.parse().ok()?,
            })
        })
        .collect()
}

/// `/proc/net/*` dosyalarından soket tablosu (okunamayanlar atlanır).
#[must_use]
pub fn proc_net_dump() -> Vec<SocketEntry> {
    [
        (Transport::Tcp, "/proc/net/tcp"),
        (Transport::Tcp, "/proc/net/tcp6"),
        (Transport::Udp, "/proc/net/udp"),
        (Transport::Udp, "/proc/net/udp6"),
    ]
    .into_iter()
    .filter_map(|(t, p)| Some(parse_proc_net(t, &fs::read_to_string(p).ok()?)))
    .flatten()
    .collect()
}

/// `socket:[12345]` → 12345.
fn socket_inode(link: &str) -> Option<u64> {
    link.strip_prefix("socket:[")?
        .strip_suffix(']')?
        .parse()
        .ok()
}

/// Tüm erişilebilir süreçlerin fd'lerini tarar: soket inode → süreç.
fn scan_proc_fds() -> HashMap<u64, ProcessInfo> {
    let mut map = HashMap::new();
    let Ok(dir) = fs::read_dir("/proc") else {
        return map;
    };
    for ent in dir.flatten() {
        let Some(pid) = ent.file_name().to_str().and_then(|s| s.parse::<u32>().ok()) else {
            continue;
        };
        let Ok(fds) = fs::read_dir(ent.path().join("fd")) else {
            continue; // izin yok
        };
        let mut name: Option<String> = None;
        for fd in fds.flatten() {
            let Some(inode) = fs::read_link(fd.path())
                .ok()
                .and_then(|l| l.to_str().and_then(socket_inode))
            else {
                continue;
            };
            let n = name.get_or_insert_with(|| {
                fs::read_to_string(ent.path().join("comm"))
                    .map(|s| s.trim_end().to_owned())
                    .unwrap_or_default()
            });
            map.entry(inode).or_insert_with(|| ProcessInfo {
                pid,
                name: n.clone(),
                inode,
            });
        }
    }
    map
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{TcpListener, UdpSocket};

    const TCP4: &str = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 123456 1 0000000000000000 100 0 0 10 0
   1: 0A01A8C0:C822 08080808:0035 01 00000000:00000000 00:00000000 00000000  1000        0 777 1 0000000000000000 20 4 30 10 -1
   garbage line
";
    const TCP6: &str = "  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000001000000:0016 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 4242 1 0000000000000000 100 0 0 10 0
   1: 0000000000000000FFFF00000100007F:1F90 0000000000000000FFFF00000100007F:D431 01 00000000:00000000 00:00000000 00000000  1000        0 99 1 0000000000000000 20 4 30 10 -1
   2: B80D0120000000000000000001000000:01BB 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 5 1 0000000000000000 100 0 0 10 0
";

    #[test]
    #[cfg(target_endian = "little")]
    fn proc_net_tcp4() {
        let v = parse_proc_net(Transport::Tcp, TCP4);
        assert_eq!(v.len(), 2);
        assert_eq!(v[0].local, "127.0.0.1:8080".parse().unwrap());
        assert_eq!(v[0].remote, "0.0.0.0:0".parse().unwrap());
        assert_eq!(v[0].inode, 123_456);
        assert_eq!(v[1].local, "192.168.1.10:51234".parse().unwrap());
        assert_eq!(v[1].remote, "8.8.8.8:53".parse().unwrap());
    }

    #[test]
    #[cfg(target_endian = "little")]
    fn proc_net_tcp6() {
        let v = parse_proc_net(Transport::Tcp, TCP6);
        assert_eq!(v.len(), 3);
        assert_eq!(v[0].local, "[::1]:22".parse().unwrap());
        assert_eq!(v[1].local, "[::ffff:127.0.0.1]:8080".parse().unwrap());
        assert_eq!(v[1].remote.port(), 0xD431);
        assert_eq!(canon_sock(v[1].local), "127.0.0.1:8080".parse().unwrap());
        assert_eq!(v[2].local, "[2001:db8::1]:443".parse().unwrap());
        assert_eq!(v[0].inode, 4242);
    }

    #[test]
    fn diag_request_layout() {
        let r = diag_request(AF_INET6, Transport::Udp, 7);
        assert_eq!(r.len(), 72);
        assert_eq!(ne_u32(&r, 0), Some(72));
        assert_eq!(ne_u16(&r, 4), Some(SOCK_DIAG_BY_FAMILY));
        assert_eq!(ne_u16(&r, 6), Some(0x301));
        assert_eq!(&r[16..20], &[AF_INET6, 17, 0, 0]);
        assert_eq!(ne_u32(&r, 20), Some(u32::MAX));
    }

    #[test]
    fn socket_link() {
        assert_eq!(socket_inode("socket:[31337]"), Some(31337));
        assert_eq!(socket_inode("pipe:[1]"), None);
    }

    fn check_self(backend: Backend) {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let u = UdpSocket::bind("[::1]:0").unwrap();
        let uaddr = u.local_addr().unwrap();
        let mut r = ProcessResolver::new(backend).with_min_interval(Duration::ZERO);
        r.force_refresh();
        assert_eq!(r.used_sock_diag(), backend == Backend::SockDiag);
        let me = std::process::id();
        let p = r
            .lookup(Transport::Tcp, addr, "10.0.0.1:1234".parse().unwrap())
            .cloned()
            .expect("tcp listener bulunmalı");
        assert_eq!(p.pid, me);
        assert_ne!(p.name, "");
        let p = r
            .lookup(Transport::Udp, uaddr, "[::1]:9".parse().unwrap())
            .expect("udp soketi bulunmalı");
        assert_eq!(p.pid, me);
        assert!(r
            .lookup(Transport::Udp, "127.0.0.1:1".parse().unwrap(), addr)
            .is_none());
    }

    #[test]
    fn live_sock_diag() {
        assert_ne!(sock_diag_dump().unwrap(), vec![]);
        check_self(Backend::SockDiag);
    }

    #[test]
    fn live_proc() {
        check_self(Backend::Proc);
    }

    #[test]
    fn live_lookup_packet() {
        use crate::testutil::{dissect_bytes, hex};
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        // 127.0.0.1:40000 → 127.0.0.1:<port> TCP SYN (eth + ip + tcp).
        let mut f = hex("000000000000000000000000080045000028000100004006 0000\
            7f0000017f000001 9c40 0050 00000000 00000000 5002ffff00000000");
        f[36..38].copy_from_slice(&port.to_be_bytes());
        let d = dissect_bytes(f);
        let mut r = ProcessResolver::default();
        let p = r.lookup_packet(&d).expect("hedef yerel dinleyici");
        assert_eq!(p.pid, std::process::id());
    }
}
