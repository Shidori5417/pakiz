//! Yakalama filtresi (`-f`): tcpdump benzeri küçük bir alt kümeyi klasik BPF'e derler.
//!
//! Gramer: `tcp`, `udp`, `icmp`, `arp`, `ip`, `ip6`, `[src|dst] host A.B.C.D`,
//! `[src|dst] port N`; `and`/`&&`, `or`/`||`, `not`/`!` ve parantez.
//! VLAN'sız Ethernet varsayılır; `host`/`port` yalnızca IPv4 (port: TCP/UDP,
//! parçalanmamış). `tcp`/`udp` IPv4 ve (uzantı başlıksız) IPv6'yı kapsar.

// Klasik BPF terminolojisi: a/x yazmaçları, k/t/f atlama hedefleri.
#![allow(clippy::many_single_char_names)]

use std::net::Ipv4Addr;

use crate::FilterError;

/// `struct sock_filter` eşdeğeri.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SockFilter {
    pub code: u16,
    pub jt: u8,
    pub jf: u8,
    pub k: u32,
}

impl SockFilter {
    #[must_use]
    pub const fn stmt(code: u16, k: u32) -> Self {
        Self {
            code,
            jt: 0,
            jf: 0,
            k,
        }
    }
}

/// Kabul edilen paketler için dönen uzunluk.
pub const SNAPLEN: u32 = 262_144;

// Klasik BPF opcode parçaları.
pub const LD: u16 = 0x00;
pub const LDX: u16 = 0x01;
pub const ALU: u16 = 0x04;
pub const JMP: u16 = 0x05;
pub const RET: u16 = 0x06;
pub const MISC: u16 = 0x07;
pub const W: u16 = 0x00;
pub const H: u16 = 0x08;
pub const B: u16 = 0x10;
pub const IMM: u16 = 0x00;
pub const ABS: u16 = 0x20;
pub const IND: u16 = 0x40;
pub const MSH: u16 = 0xa0;
pub const JA: u16 = 0x00;
pub const JEQ: u16 = 0x10;
pub const JGT: u16 = 0x20;
pub const JGE: u16 = 0x30;
pub const JSET: u16 = 0x40;
pub const ADD: u16 = 0x00;
pub const AND: u16 = 0x50;
pub const K: u16 = 0x00;
pub const X: u16 = 0x08;
pub const A: u16 = 0x10;
pub const TAX: u16 = 0x00;
pub const TXA: u16 = 0x80;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Dir {
    Src,
    Dst,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Bx {
    And(Box<Bx>, Box<Bx>),
    Or(Box<Bx>, Box<Bx>),
    Not(Box<Bx>),
    /// `ldh [12]; jeq #t`
    EtherType(u16),
    /// IPv4 olduğu varsayılır: `ldb [23]; jeq #p`
    Ip4Proto(u8),
    /// IPv6 olduğu varsayılır: `ldb [20]; jeq #p`
    Ip6Proto(u8),
    /// IPv4 varsayılır: `ld [26|30]; jeq #a`
    Ip4Addr(Dir, u32),
    /// IPv4 varsayılır: parça ofseti 0 mı?
    NotFrag,
    /// IPv4 TCP/UDP varsayılır: `ldxb 4*([14]&0xf); ldh [x+14|16]; jeq #n`
    L4Port(Dir, u16),
}

fn and(a: Bx, b: Bx) -> Bx {
    Bx::And(Box::new(a), Box::new(b))
}
fn or(a: Bx, b: Bx) -> Bx {
    Bx::Or(Box::new(a), Box::new(b))
}

const ETH_IP: u16 = 0x0800;
const ETH_IP6: u16 = 0x86dd;
const ETH_ARP: u16 = 0x0806;

fn l4(proto: u8) -> Bx {
    or(
        and(Bx::EtherType(ETH_IP), Bx::Ip4Proto(proto)),
        and(Bx::EtherType(ETH_IP6), Bx::Ip6Proto(proto)),
    )
}

/// Yakalama filtresini derler. Boş kaynak her paketi kabul eder.
///
/// # Errors
/// Bilinmeyen kelime, eksik argüman, parantez hatası veya 255'i aşan atlama.
pub fn compile(src: &str) -> Result<Vec<SockFilter>, FilterError> {
    let toks = tokenize(src);
    if toks.is_empty() {
        return Ok(vec![SockFilter::stmt(RET | K, SNAPLEN)]);
    }
    let mut p = P {
        toks,
        pos: 0,
        end: src.len(),
    };
    let e = p.or()?;
    if let Some((_, s)) = p.toks.get(p.pos) {
        return Err(FilterError::new(s.clone(), "beklenmeyen sözcük"));
    }
    let mut g = Gen {
        rev: vec![
            SockFilter::stmt(RET | K, 0),
            SockFilter::stmt(RET | K, SNAPLEN),
        ],
    };
    g.gen(&e, 1, 0)
        .map_err(|()| FilterError::new(0..src.len(), "filtre çok büyük (atlama > 255)"))?;
    g.rev.reverse();
    Ok(g.rev)
}

fn tokenize(src: &str) -> Vec<(&str, std::ops::Range<usize>)> {
    let b = src.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        if c.is_ascii_whitespace() {
            i += 1;
            continue;
        }
        let len = if matches!(c, b'(' | b')') || (c == b'!' && b.get(i + 1) != Some(&b'=')) {
            1
        } else if src[i..].starts_with("&&") || src[i..].starts_with("||") {
            2
        } else {
            src[i..]
                .find(|ch: char| ch.is_ascii_whitespace() || "()!&|".contains(ch))
                .unwrap_or(src.len() - i)
                .max(1)
        };
        out.push((&src[i..i + len], i..i + len));
        i += len;
    }
    out
}

struct P<'a> {
    toks: Vec<(&'a str, std::ops::Range<usize>)>,
    pos: usize,
    end: usize,
}

impl P<'_> {
    fn peek(&self) -> Option<&str> {
        self.toks.get(self.pos).map(|t| t.0)
    }

    fn next(&mut self) -> Result<(&str, std::ops::Range<usize>), FilterError> {
        let t = self
            .toks
            .get(self.pos)
            .cloned()
            .ok_or_else(|| FilterError::new(self.end..self.end, "beklenmedik ifade sonu"))?;
        self.pos += 1;
        Ok(t)
    }

    fn or(&mut self) -> Result<Bx, FilterError> {
        let mut l = self.and()?;
        while matches!(self.peek(), Some("or" | "||")) {
            self.pos += 1;
            l = or(l, self.and()?);
        }
        Ok(l)
    }

    fn and(&mut self) -> Result<Bx, FilterError> {
        let mut l = self.unary()?;
        while matches!(self.peek(), Some("and" | "&&")) {
            self.pos += 1;
            l = and(l, self.unary()?);
        }
        Ok(l)
    }

    fn unary(&mut self) -> Result<Bx, FilterError> {
        let (w, span) = self.next()?;
        Ok(match w {
            "not" | "!" => Bx::Not(Box::new(self.unary()?)),
            "(" => {
                let e = self.or()?;
                match self.next() {
                    Ok((")", _)) => e,
                    Ok((_, s)) => return Err(FilterError::new(s, "')' bekleniyordu")),
                    Err(_) => return Err(FilterError::new(span, "kapanmamış parantez")),
                }
            }
            "ip" => Bx::EtherType(ETH_IP),
            "ip6" => Bx::EtherType(ETH_IP6),
            "arp" => Bx::EtherType(ETH_ARP),
            "tcp" => l4(6),
            "udp" => l4(17),
            "icmp" => and(Bx::EtherType(ETH_IP), Bx::Ip4Proto(1)),
            "src" | "dst" => {
                let d = if w == "src" { Dir::Src } else { Dir::Dst };
                self.qualified(Some(d))?
            }
            "host" | "port" => {
                self.pos -= 1;
                self.qualified(None)?
            }
            _ => return Err(FilterError::new(span, format!("bilinmeyen ilkel: {w}"))),
        })
    }

    fn qualified(&mut self, dir: Option<Dir>) -> Result<Bx, FilterError> {
        let (kind, ks) = self.next()?;
        let kind = kind.to_owned();
        let (arg, span) = self.next()?;
        let both = |f: &dyn Fn(Dir) -> Bx| match dir {
            Some(d) => f(d),
            None => or(f(Dir::Src), f(Dir::Dst)),
        };
        match kind.as_str() {
            "host" => {
                let a: Ipv4Addr = arg
                    .parse()
                    .map_err(|_| FilterError::new(span, format!("geçersiz IPv4 adresi: {arg}")))?;
                let a = u32::from(a);
                Ok(and(Bx::EtherType(ETH_IP), both(&|d| Bx::Ip4Addr(d, a))))
            }
            "port" => {
                let n: u16 = arg
                    .parse()
                    .map_err(|_| FilterError::new(span, format!("geçersiz port: {arg}")))?;
                Ok(and(
                    and(
                        and(Bx::EtherType(ETH_IP), or(Bx::Ip4Proto(6), Bx::Ip4Proto(17))),
                        Bx::NotFrag,
                    ),
                    both(&|d| Bx::L4Port(d, n)),
                ))
            }
            _ => Err(FilterError::new(ks, "'host' veya 'port' bekleniyordu")),
        }
    }
}

/// Programı sondan başa üretir: atlama hedefleri her zaman zaten üretilmiş
/// (programda sonra gelen) talimatlardır; `rev[i]`'nin sondan konumu `i`'dir.
struct Gen {
    rev: Vec<SockFilter>,
}

impl Gen {
    fn push(&mut self, s: SockFilter) -> usize {
        self.rev.push(s);
        self.rev.len() - 1
    }

    fn jump(&mut self, code: u16, k: u32, t: usize, f: usize) -> Result<usize, ()> {
        let here = self.rev.len();
        let off = |to: usize| u8::try_from(here - to - 1).map_err(|_| ());
        let s = SockFilter {
            code: JMP | code | K,
            jt: off(t)?,
            jf: off(f)?,
            k,
        };
        Ok(self.push(s))
    }

    /// `e` doğruysa `t`'ye, değilse `f`'ye gider; giriş konumunu döner.
    fn gen(&mut self, e: &Bx, t: usize, f: usize) -> Result<usize, ()> {
        Ok(match *e {
            Bx::And(ref a, ref b) => {
                let eb = self.gen(b, t, f)?;
                self.gen(a, eb, f)?
            }
            Bx::Or(ref a, ref b) => {
                let eb = self.gen(b, t, f)?;
                self.gen(a, t, eb)?
            }
            Bx::Not(ref a) => self.gen(a, f, t)?,
            Bx::EtherType(ty) => {
                self.jump(JEQ, u32::from(ty), t, f)?;
                self.push(SockFilter::stmt(LD | H | ABS, 12))
            }
            Bx::Ip4Proto(p) => {
                self.jump(JEQ, u32::from(p), t, f)?;
                self.push(SockFilter::stmt(LD | B | ABS, 23))
            }
            Bx::Ip6Proto(p) => {
                self.jump(JEQ, u32::from(p), t, f)?;
                self.push(SockFilter::stmt(LD | B | ABS, 20))
            }
            Bx::Ip4Addr(d, a) => {
                self.jump(JEQ, a, t, f)?;
                let off = if d == Dir::Src { 26 } else { 30 };
                self.push(SockFilter::stmt(LD | W | ABS, off))
            }
            Bx::NotFrag => {
                self.jump(JSET, 0x1fff, f, t)?;
                self.push(SockFilter::stmt(LD | H | ABS, 20))
            }
            Bx::L4Port(d, n) => {
                self.jump(JEQ, u32::from(n), t, f)?;
                let off = if d == Dir::Src { 14 } else { 16 };
                self.push(SockFilter::stmt(LD | H | IND, off));
                self.push(SockFilter::stmt(LDX | B | MSH, 14))
            }
        })
    }
}

/// Saf Rust klasik BPF yorumlayıcısı (test/doğrulama için). Dönen değer
/// kabul edilen uzunluk; 0 = reddet. Sınır dışı okuma veya geçersiz talimat 0 döner.
#[must_use]
pub fn run(prog: &[SockFilter], pkt: &[u8]) -> u32 {
    let (mut a, mut x) = (0u32, 0u32);
    let mut pc = 0usize;
    let load = |off: u32, size: u16| -> Option<u32> {
        let o = usize::try_from(off).ok()?;
        let n = match size {
            W => 4,
            H => 2,
            _ => 1,
        };
        let s = pkt.get(o..o.checked_add(n)?)?;
        Some(s.iter().fold(0u32, |acc, &b| (acc << 8) | u32::from(b)))
    };
    while let Some(ins) = prog.get(pc) {
        pc += 1;
        let c = ins.code;
        let k = ins.k;
        match c & 0x07 {
            LD => {
                let v = match c & 0xe0 {
                    IMM => Some(k),
                    ABS => load(k, c & 0x18),
                    IND => load(x.wrapping_add(k), c & 0x18),
                    _ => None,
                };
                let Some(v) = v else { return 0 };
                a = v;
            }
            LDX => {
                x = match c & 0xe0 {
                    IMM => k,
                    MSH => match load(k, B) {
                        Some(v) => (v & 0x0f) * 4,
                        None => return 0,
                    },
                    _ => return 0,
                };
            }
            ALU => {
                let src = if c & X == X { x } else { k };
                a = match c & 0xf0 {
                    ADD => a.wrapping_add(src),
                    AND => a & src,
                    _ => return 0,
                };
            }
            JMP => {
                let src = if c & X == X { x } else { k };
                let taken = match c & 0xf0 {
                    JA => {
                        pc = pc.saturating_add(usize::try_from(k).unwrap_or(usize::MAX));
                        continue;
                    }
                    JEQ => a == src,
                    JGT => a > src,
                    JGE => a >= src,
                    JSET => a & src != 0,
                    _ => return 0,
                };
                pc += usize::from(if taken { ins.jt } else { ins.jf });
            }
            RET => return if c & 0x18 == A { a } else { k },
            MISC => {
                if c & 0xf8 == TXA {
                    a = x;
                } else {
                    x = a;
                }
            }
            _ => return 0,
        }
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_accepts_all() {
        let p = compile("  ").unwrap();
        assert_eq!(p, [SockFilter::stmt(RET | K, SNAPLEN)]);
        assert_eq!(run(&p, &[]), SNAPLEN);
    }

    #[test]
    fn ip_program_shape() {
        // tcpdump -d ip ile aynı yapı.
        let p = compile("ip").unwrap();
        assert_eq!(
            p,
            [
                SockFilter::stmt(LD | H | ABS, 12),
                SockFilter {
                    code: JMP | JEQ | K,
                    jt: 0,
                    jf: 1,
                    k: 0x800
                },
                SockFilter::stmt(RET | K, SNAPLEN),
                SockFilter::stmt(RET | K, 0),
            ]
        );
    }

    #[test]
    fn interpreter_basics() {
        let p = [
            SockFilter::stmt(LD | IMM, 5),
            SockFilter::stmt(MISC | TAX, 0),
            SockFilter::stmt(ALU | ADD | X, 0),
            SockFilter::stmt(ALU | AND | K, 0xff),
            SockFilter::stmt(JMP | JA, 1),
            SockFilter::stmt(RET | K, 1),
            SockFilter::stmt(RET | A, 0),
        ];
        assert_eq!(run(&p, &[]), 10);
        // Sınır dışı okuma reddeder.
        assert_eq!(run(&[SockFilter::stmt(LD | W | ABS, 100)], &[0; 4]), 0);
        // Sonu RET'siz program reddeder.
        assert_eq!(run(&[], &[]), 0);
    }

    #[test]
    fn errors() {
        assert_eq!(compile("tcpx").unwrap_err().span, 0..4);
        assert_eq!(compile("port").unwrap_err().span, 4..4);
        assert!(compile("port 70000").is_err());
        assert!(compile("host 1.2.3").is_err());
        assert!(compile("src foo 1").is_err());
        assert!(compile("(tcp").is_err());
        assert!(compile("tcp udp").is_err());
        assert!(compile("tcp and").is_err());
    }
}
