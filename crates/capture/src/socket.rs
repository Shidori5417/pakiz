//! `AF_PACKET` soketi ve `TPACKET_V3` halka tamponu. Crate'teki tüm `unsafe` burada.

use std::mem::{size_of, MaybeUninit};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::ptr::{self, NonNull};
use std::sync::atomic::{fence, AtomicBool, Ordering};
use std::time::{Duration, SystemTime};

use pakiz_dissect::RawPacket;

use crate::error::{last_os_error, Result};

/// Klasik BPF komutu (`struct sock_filter`).
pub use libc::sock_filter;

#[allow(clippy::cast_possible_truncation)] // ETH_P_ALL = 0x0003
const ETH_P_ALL_BE: u16 = (libc::ETH_P_ALL as u16).to_be();

/// Kernel'den alınan sayaçlar.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct KernelStats {
    pub received: u64,
    pub dropped: u64,
}

fn setsockopt<T>(fd: RawFd, level: i32, name: i32, val: &T, op: &'static str) -> Result<()> {
    #[allow(clippy::cast_possible_truncation)] // option yapıları küçük
    let len = size_of::<T>() as libc::socklen_t;
    // SAFETY: `val` geçerli, hizalı ve `len` bayt boyunca okunabilir bir referans;
    // kernel yalnızca okur. `fd` çağıranın sahip olduğu açık bir soket.
    let rc = unsafe { libc::setsockopt(fd, level, name, ptr::from_ref(val).cast(), len) };
    if rc == 0 {
        Ok(())
    } else {
        Err(last_os_error(op))
    }
}

/// Arayüze bağlı `AF_PACKET/SOCK_RAW/ETH_P_ALL` soketi.
#[derive(Debug)]
pub struct PacketSocket {
    fd: OwnedFd,
    ifindex: u32,
    promisc: AtomicBool,
}

impl PacketSocket {
    /// Soketi açar (henüz bind edilmemiş).
    ///
    /// # Errors
    /// Yetki yoksa [`crate::CaptureError::Permission`].
    pub fn open(ifindex: u32) -> Result<Self> {
        // SAFETY: argümanları sabit olan basit sistem çağrısı; dönen fd kontrol ediliyor.
        let fd = unsafe {
            libc::socket(
                libc::AF_PACKET,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                i32::from(ETH_P_ALL_BE),
            )
        };
        if fd < 0 {
            return Err(last_os_error("socket(AF_PACKET)"));
        }
        // SAFETY: `fd` az önce açıldı, geçerli ve başka hiçbir yerde sahiplenilmedi.
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        Ok(Self {
            fd,
            ifindex,
            promisc: AtomicBool::new(false),
        })
    }

    #[must_use]
    pub fn ifindex(&self) -> u32 {
        self.ifindex
    }

    pub(crate) fn raw(&self) -> RawFd {
        self.fd.as_raw_fd()
    }

    /// Soketi arayüze bağlar.
    ///
    /// # Errors
    /// `bind` başarısızsa.
    pub fn bind(&self) -> Result<()> {
        // SAFETY: sockaddr_ll tamamen sayısal alanlardan oluşur; sıfır geçerli bir değer.
        let mut sll: libc::sockaddr_ll = unsafe { MaybeUninit::zeroed().assume_init() };
        #[allow(clippy::cast_possible_truncation)]
        {
            sll.sll_family = libc::AF_PACKET as u16;
        }
        sll.sll_protocol = ETH_P_ALL_BE;
        sll.sll_ifindex = i32::try_from(self.ifindex).unwrap_or(0);
        #[allow(clippy::cast_possible_truncation)]
        let len = size_of::<libc::sockaddr_ll>() as libc::socklen_t;
        // SAFETY: `sll` geçerli bir sockaddr_ll ve `len` onun boyutu; kernel yalnızca okur.
        let rc = unsafe { libc::bind(self.raw(), ptr::from_ref(&sll).cast(), len) };
        if rc == 0 {
            Ok(())
        } else {
            Err(last_os_error("bind(AF_PACKET)"))
        }
    }

    /// Promiscuous modu açar/kapatır (`PACKET_ADD/DROP_MEMBERSHIP`, `PACKET_MR_PROMISC`).
    ///
    /// # Errors
    /// `setsockopt` başarısızsa.
    pub fn set_promisc(&self, on: bool) -> Result<()> {
        if self.promisc.load(Ordering::Acquire) == on {
            return Ok(());
        }
        let mreq = libc::packet_mreq {
            mr_ifindex: i32::try_from(self.ifindex).unwrap_or(0),
            #[allow(clippy::cast_possible_truncation)]
            mr_type: libc::PACKET_MR_PROMISC as u16,
            mr_alen: 0,
            mr_address: [0; 8],
        };
        let name = if on {
            libc::PACKET_ADD_MEMBERSHIP
        } else {
            libc::PACKET_DROP_MEMBERSHIP
        };
        setsockopt(
            self.raw(),
            libc::SOL_PACKET,
            name,
            &mreq,
            "PACKET_MR_PROMISC",
        )?;
        self.promisc.store(on, Ordering::Release);
        Ok(())
    }

    /// Klasik BPF programını bağlar (`SO_ATTACH_FILTER`).
    ///
    /// # Errors
    /// Program boş/çok uzunsa ya da kernel reddederse.
    pub fn attach_filter(&self, prog: &[sock_filter]) -> Result<()> {
        let Ok(len) = u16::try_from(prog.len()) else {
            return Err(crate::CaptureError::Io {
                op: "SO_ATTACH_FILTER",
                source: std::io::Error::from(std::io::ErrorKind::InvalidInput),
            });
        };
        let fprog = libc::sock_fprog {
            len,
            // Kernel programı yalnızca okur; mut işaretçi C API imzası gereği.
            filter: prog.as_ptr().cast_mut(),
        };
        setsockopt(
            self.raw(),
            libc::SOL_SOCKET,
            libc::SO_ATTACH_FILTER,
            &fprog,
            "SO_ATTACH_FILTER",
        )
    }

    /// `PACKET_STATISTICS` okur. Kernel sayaçları her okumada sıfırlar (delta döner).
    ///
    /// # Errors
    /// `getsockopt` başarısızsa.
    pub fn stats_delta(&self) -> Result<KernelStats> {
        // V3 soketinde kernel tpacket_stats_v3, diğerlerinde tpacket_stats (ilk iki alan
        // aynı düzende) yazar; büyük olan yapıyla okumak ikisini de kapsar.
        let mut st = libc::tpacket_stats_v3 {
            tp_packets: 0,
            tp_drops: 0,
            tp_freeze_q_cnt: 0,
        };
        #[allow(clippy::cast_possible_truncation)]
        let mut len = size_of::<libc::tpacket_stats_v3>() as libc::socklen_t;
        // SAFETY: `st` yazılabilir ve `len` bayt büyüklüğünde; kernel en fazla `len` yazar.
        let rc = unsafe {
            libc::getsockopt(
                self.raw(),
                libc::SOL_PACKET,
                libc::PACKET_STATISTICS,
                ptr::from_mut(&mut st).cast(),
                &raw mut len,
            )
        };
        if rc != 0 {
            return Err(last_os_error("PACKET_STATISTICS"));
        }
        Ok(KernelStats {
            received: u64::from(st.tp_packets),
            dropped: u64::from(st.tp_drops),
        })
    }

    fn set_rcvtimeo(&self, d: Duration) -> Result<()> {
        let tv = libc::timeval {
            tv_sec: libc::time_t::try_from(d.as_secs()).unwrap_or(1),
            tv_usec: libc::suseconds_t::from(d.subsec_micros()),
        };
        setsockopt(
            self.raw(),
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            &tv,
            "SO_RCVTIMEO",
        )
    }

    /// `recvfrom` yolu: stop bayrağı kalkana dek okur, her paketi `emit`'e verir.
    pub(crate) fn recv_loop(
        &self,
        skip_outgoing: bool,
        stop: &AtomicBool,
        mut emit: impl FnMut(RawPacket),
    ) -> Result<()> {
        self.set_rcvtimeo(Duration::from_millis(100))?;
        let mut buf = vec![0u8; 65536];
        while !stop.load(Ordering::Relaxed) {
            // SAFETY: sockaddr_ll sayısal alanlardan oluşur; sıfır geçerli.
            let mut from: libc::sockaddr_ll = unsafe { MaybeUninit::zeroed().assume_init() };
            #[allow(clippy::cast_possible_truncation)]
            let mut flen = size_of::<libc::sockaddr_ll>() as libc::socklen_t;
            // SAFETY: `buf` `buf.len()` bayt yazılabilir; `from`/`flen` geçerli çıkış
            // tamponları. MSG_TRUNC yalnızca dönüş değerini (gerçek uzunluk) etkiler.
            let n = unsafe {
                libc::recvfrom(
                    self.raw(),
                    buf.as_mut_ptr().cast(),
                    buf.len(),
                    libc::MSG_TRUNC,
                    ptr::from_mut(&mut from).cast(),
                    &raw mut flen,
                )
            };
            let Ok(n) = usize::try_from(n) else {
                let err = std::io::Error::last_os_error();
                match err.raw_os_error() {
                    Some(libc::EAGAIN | libc::EINTR) => continue,
                    _ => return Err(crate::error::from_io("recvfrom", err)),
                }
            };
            if skip_outgoing && from.sll_pkttype == libc::PACKET_OUTGOING {
                continue;
            }
            let caplen = n.min(buf.len());
            emit(RawPacket {
                ts: SystemTime::now(),
                data: buf[..caplen].to_vec(),
                orig_len: u32::try_from(n).unwrap_or(u32::MAX),
                ifindex: u32::try_from(from.sll_ifindex).unwrap_or(self.ifindex),
            });
        }
        Ok(())
    }

    /// stop bayrağına bakarak en fazla `timeout_ms` bekler.
    fn poll_in(&self, timeout_ms: i32) -> Result<()> {
        let mut pfd = libc::pollfd {
            fd: self.raw(),
            events: libc::POLLIN | libc::POLLERR,
            revents: 0,
        };
        // SAFETY: `pfd` tek elemanlı geçerli bir pollfd dizisi.
        let rc = unsafe { libc::poll(&raw mut pfd, 1, timeout_ms) };
        if rc < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() != Some(libc::EINTR) {
                return Err(crate::error::from_io("poll", err));
            }
        }
        Ok(())
    }
}

impl Drop for PacketSocket {
    fn drop(&mut self) {
        // Soket kapanınca kernel üyeliği zaten düşürür; açıkça kapatmak niyeti netleştirir.
        let _ = self.set_promisc(false);
    }
}

/// `TPACKET_V3` mmap halka tamponu.
pub(crate) struct Ring {
    base: NonNull<u8>,
    block_size: usize,
    block_nr: usize,
}

// SAFETY: `Ring` mmap bölgesinin tek sahibidir; yalnızca sahip olan thread erişir
// (kernel ile senkronizasyon block_status + bellek bariyerleriyle yapılır).
unsafe impl Send for Ring {}

const BLOCK_SIZE: u32 = 1 << 20; // 1 MiB
const BLOCK_NR: u32 = 32;
const FRAME_SIZE: u32 = 2048;
const RETIRE_TOV_MS: u32 = 50;

impl Ring {
    /// Soketi `TPACKET_V3`'e geçirir ve RX ring'i map eder.
    pub(crate) fn setup(sock: &PacketSocket) -> Result<Self> {
        let ver = libc::tpacket_versions::TPACKET_V3 as libc::c_int;
        setsockopt(
            sock.raw(),
            libc::SOL_PACKET,
            libc::PACKET_VERSION,
            &ver,
            "PACKET_VERSION",
        )?;
        let req = libc::tpacket_req3 {
            tp_block_size: BLOCK_SIZE,
            tp_block_nr: BLOCK_NR,
            tp_frame_size: FRAME_SIZE,
            tp_frame_nr: BLOCK_SIZE / FRAME_SIZE * BLOCK_NR,
            tp_retire_blk_tov: RETIRE_TOV_MS,
            tp_sizeof_priv: 0,
            tp_feature_req_word: 0,
        };
        setsockopt(
            sock.raw(),
            libc::SOL_PACKET,
            libc::PACKET_RX_RING,
            &req,
            "PACKET_RX_RING",
        )?;
        let block_size = BLOCK_SIZE as usize;
        let block_nr = BLOCK_NR as usize;
        // SAFETY: NULL adresli yeni bir paylaşımlı eşleme isteniyor; boyut ring'in
        // toplam boyutu. Sonuç MAP_FAILED'e karşı kontrol ediliyor.
        let p = unsafe {
            libc::mmap(
                ptr::null_mut(),
                block_size * block_nr,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                sock.raw(),
                0,
            )
        };
        if p == libc::MAP_FAILED {
            let err = last_os_error("mmap(PACKET_RX_RING)");
            // Ring kurulu kalırsa recvfrom paket almaz; recv yoluna düşebilmek için sök.
            let zero = libc::tpacket_req3 {
                tp_block_size: 0,
                tp_block_nr: 0,
                tp_frame_size: 0,
                tp_frame_nr: 0,
                tp_retire_blk_tov: 0,
                tp_sizeof_priv: 0,
                tp_feature_req_word: 0,
            };
            let _ = setsockopt(
                sock.raw(),
                libc::SOL_PACKET,
                libc::PACKET_RX_RING,
                &zero,
                "PACKET_RX_RING",
            );
            return Err(err);
        }
        let base = NonNull::new(p.cast::<u8>()).ok_or_else(|| last_os_error("mmap"))?;
        Ok(Self {
            base,
            block_size,
            block_nr,
        })
    }

    /// Block'ları sırayla okur; dolu block yoksa poll ile bekler.
    pub(crate) fn run(
        &self,
        sock: &PacketSocket,
        skip_outgoing: bool,
        stop: &AtomicBool,
        mut emit: impl FnMut(RawPacket),
    ) -> Result<()> {
        let mut idx = 0usize;
        while !stop.load(Ordering::Relaxed) {
            // SAFETY: idx < block_nr, dolayısıyla ofset map edilen bölgenin içinde.
            let block = unsafe { self.base.as_ptr().add(idx * self.block_size) };
            #[allow(clippy::cast_ptr_alignment)] // mmap sayfa hizalı, block_size sayfa katı
            let bd = block.cast::<libc::tpacket_block_desc>();
            // SAFETY: Her block başında kernel'in yazdığı hizalı bir tpacket_block_desc
            // bulunur; V3'te birliğin tek üyesi bh1'dir. Kernel eşzamanlı yazdığı için
            // volatile okunur.
            let status_ptr = unsafe { &raw mut (*bd).hdr.bh1.block_status };
            // SAFETY: status_ptr geçerli ve hizalı (yukarıya bkz).
            let status = unsafe { ptr::read_volatile(status_ptr) };
            if status & libc::TP_STATUS_USER == 0 {
                sock.poll_in(100)?;
                continue;
            }
            fence(Ordering::Acquire);
            // SAFETY: TP_STATUS_USER görüldü; block artık kullanıcıya ait ve
            // kernel tarafından değiştirilmiyor.
            let (num, first) = unsafe {
                let h = &(*bd).hdr.bh1;
                (h.num_pkts, h.offset_to_first_pkt as usize)
            };
            self.walk_block(block, num, first, sock.ifindex(), skip_outgoing, &mut emit);
            fence(Ordering::Release);
            // SAFETY: block'u kernel'e geri veriyoruz; status_ptr geçerli.
            unsafe { ptr::write_volatile(status_ptr, libc::TP_STATUS_KERNEL) };
            idx = (idx + 1) % self.block_nr;
        }
        Ok(())
    }

    fn walk_block(
        &self,
        block: *mut u8,
        num: u32,
        mut off: usize,
        ifindex: u32,
        skip_outgoing: bool,
        emit: &mut impl FnMut(RawPacket),
    ) {
        let hdr_len = size_of::<libc::tpacket3_hdr>();
        let sll_off = (hdr_len + libc::TPACKET_ALIGNMENT - 1) & !(libc::TPACKET_ALIGNMENT - 1);
        for _ in 0..num {
            if off + sll_off + size_of::<libc::sockaddr_ll>() > self.block_size {
                return;
            }
            // SAFETY: off + başlık block sınırları içinde (yukarıda kontrol edildi);
            // hizalama garantisi için read_unaligned kullanılır.
            let h = unsafe { ptr::read_unaligned(block.add(off).cast::<libc::tpacket3_hdr>()) };
            // SAFETY: sockaddr_ll, başlıktan sonra TPACKET_ALIGN ile hizalı ofsette ve
            // block içinde (yukarıda kontrol edildi).
            let sll = unsafe {
                ptr::read_unaligned(block.add(off + sll_off).cast::<libc::sockaddr_ll>())
            };
            let start = off + usize::from(h.tp_mac);
            let len = h.tp_snaplen as usize;
            if start + len > self.block_size {
                return;
            }
            if !(skip_outgoing && sll.sll_pkttype == libc::PACKET_OUTGOING) {
                // SAFETY: [start, start+len) block içinde (yukarıda kontrol edildi) ve
                // block kullanıcıya ait olduğu sürece kernel bu bölgeye yazmaz.
                let data = unsafe { std::slice::from_raw_parts(block.add(start), len) };
                emit(RawPacket {
                    ts: SystemTime::UNIX_EPOCH
                        + Duration::new(u64::from(h.tp_sec), h.tp_nsec.min(999_999_999)),
                    data: data.to_vec(),
                    orig_len: h.tp_len,
                    ifindex: u32::try_from(sll.sll_ifindex).unwrap_or(ifindex),
                });
            }
            if h.tp_next_offset == 0 {
                return;
            }
            off += h.tp_next_offset as usize;
        }
    }
}

impl Drop for Ring {
    fn drop(&mut self) {
        // SAFETY: base/boyut setup'taki başarılı mmap'ten geliyor ve yalnızca burada unmap edilir.
        unsafe {
            libc::munmap(self.base.as_ptr().cast(), self.block_size * self.block_nr);
        }
    }
}
