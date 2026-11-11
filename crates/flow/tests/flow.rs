//! Uçtan uca testler: gerçek çerçeveler → `Registry` → `FlowTable`.

#![allow(clippy::unwrap_used, clippy::too_many_lines, clippy::assert_is_empty)]

mod common;

use std::net::SocketAddr;
use std::time::Duration;

use common::{sa, Cap, Rng, Tcp, ACK, FIN, PSH, RST, SYN};
use pakiz_flow::{
    render_ascii, Config, Dir, FlowTable, KeyDir, Marker, PacketAnalysis, Proto, StreamId,
    TcpAnalysis as A, TcpState,
};

const CISN: u32 = 1000;
const SISN: u32 = 5000;

fn c() -> SocketAddr {
    sa("10.0.0.1:40000")
}
fn s() -> SocketAddr {
    sa("10.0.0.2:9000")
}

fn flags(p: &PacketAnalysis) -> Vec<A> {
    p.tcp.as_ref().unwrap().analysis.clone()
}

fn tcp0() -> StreamId {
    StreamId {
        proto: Proto::Tcp,
        index: 0,
    }
}

/// SYN, SYN-ACK, ACK. Sonrasında istemci veri seq'i CISN+1, sunucu SISN+1.
fn handshake(cap: &mut Cap, cl: SocketAddr, sv: SocketAddr, cisn: u32, sisn: u32) {
    cap.tcp(cl, sv, &Tcp::new(cisn, 0, SYN, &[]));
    cap.tcp(
        sv,
        cl,
        &Tcp::new(sisn, cisn.wrapping_add(1), SYN | ACK, &[]),
    );
    cap.tcp(
        cl,
        sv,
        &Tcp::new(cisn.wrapping_add(1), sisn.wrapping_add(1), ACK, &[]),
    );
}

fn chunks_text(t: &FlowTable, id: StreamId) -> Vec<(Dir, String)> {
    t.stream(id)
        .unwrap()
        .chunks()
        .map(|c| (c.dir, render_ascii(&c)))
        .collect()
}

#[test]
fn handshake_data_fin() {
    let mut cap = Cap::new();
    let p = cap.tcp(c(), s(), &Tcp::new(CISN, 0, SYN, &[]));
    assert_eq!(p.stream, tcp0());
    assert_eq!(p.dir, Dir::Client);
    assert_eq!(p.key_dir, KeyDir::AtoB);
    assert_eq!(p.tcp.as_ref().unwrap().rel_seq, 0);
    assert_eq!(cap.table.conversations()[0].state, Some(TcpState::SynSent));
    let p = cap.tcp(s(), c(), &Tcp::new(SISN, CISN + 1, SYN | ACK, &[]));
    assert_eq!(p.dir, Dir::Server);
    assert_eq!(p.key_dir, KeyDir::BtoA);
    let t = p.tcp.unwrap();
    assert_eq!((t.rel_seq, t.rel_ack), (0, Some(1)));
    cap.tcp(c(), s(), &Tcp::new(CISN + 1, SISN + 1, ACK, &[]));
    let p = cap.tcp(c(), s(), &Tcp::new(CISN + 1, SISN + 1, ACK | PSH, b"hello"));
    let t = p.tcp.unwrap();
    assert_eq!((t.rel_seq, t.next_rel_seq, t.len), (1, 6, 5));
    assert!(t.analysis.is_empty());
    let p = cap.tcp(s(), c(), &Tcp::new(SISN + 1, CISN + 6, ACK | PSH, b"world"));
    assert_eq!(p.tcp.as_ref().unwrap().rel_ack, Some(6));
    assert!(flags(&p).is_empty());
    assert_eq!(
        cap.table.conversations()[0].state,
        Some(TcpState::Established)
    );
    cap.tcp(c(), s(), &Tcp::new(CISN + 6, SISN + 6, FIN | ACK, &[]));
    let p = cap.tcp(s(), c(), &Tcp::new(SISN + 6, CISN + 7, FIN | ACK, &[]));
    assert!(flags(&p).is_empty());
    let p = cap.tcp(c(), s(), &Tcp::new(CISN + 7, SISN + 7, ACK, &[]));
    assert!(flags(&p).is_empty(), "{:?}", flags(&p));
    let conv = &cap.table.conversations()[0];
    assert_eq!(conv.state, Some(TcpState::Closed));
    assert_eq!(conv.packets, [5, 3]);
    assert_eq!(conv.client, c());
    assert_eq!(conv.server, s());
    assert_eq!(
        chunks_text(&cap.table, tcp0()),
        [
            (Dir::Client, "hello".to_owned()),
            (Dir::Server, "world".to_owned())
        ]
    );
}

#[test]
fn client_is_syn_sender_even_if_key_reversed() {
    let mut cap = Cap::new();
    let (cl, sv) = (sa("192.168.1.9:50000"), sa("10.0.0.1:80"));
    let p = cap.tcp(cl, sv, &Tcp::new(1, 0, SYN, &[]));
    assert_eq!(p.key_dir, KeyDir::BtoA);
    assert_eq!(p.dir, Dir::Client);
    assert_eq!(p.key.a, sv);
    let conv = &cap.table.conversations()[0];
    assert_eq!((conv.client, conv.server), (cl, sv));
}

#[test]
fn synack_first_makes_destination_client() {
    let mut cap = Cap::new();
    let p = cap.tcp(s(), c(), &Tcp::new(SISN, CISN + 1, SYN | ACK, &[]));
    assert_eq!(p.dir, Dir::Server);
    assert_eq!(cap.table.conversations()[0].client, c());
}

#[test]
fn midstream_first_sender_is_client() {
    let mut cap = Cap::new();
    let p = cap.tcp(s(), c(), &Tcp::new(777, 888, ACK, b"abc"));
    assert_eq!(p.dir, Dir::Client);
    let t = p.tcp.unwrap();
    assert_eq!(t.rel_seq, 0);
    assert_eq!(t.rel_ack, None, "karşı yön bilinmiyor");
    let p = cap.tcp(c(), s(), &Tcp::new(888, 780, ACK, b"x"));
    assert_eq!(p.tcp.unwrap().rel_ack, Some(3));
    assert_eq!(cap.table.stream(tcp0()).unwrap().data(Dir::Client), b"abc");
}

#[test]
fn out_of_order_delivery() {
    let mut cap = Cap::new();
    handshake(&mut cap, c(), s(), CISN, SISN);
    cap.step_ms = 1;
    let p = cap.tcp(c(), s(), &Tcp::new(CISN + 6, SISN + 1, ACK, b"world"));
    assert_eq!(flags(&p), [A::PreviousSegmentNotCaptured]);
    let p = cap.tcp(c(), s(), &Tcp::new(CISN + 1, SISN + 1, ACK, b"hello"));
    assert_eq!(flags(&p), [A::OutOfOrder]);
    let st = cap.table.stream(tcp0()).unwrap();
    assert_eq!(st.data(Dir::Client), b"helloworld");
    // İlk parçanın ilk paketi, "hello"yu taşıyan 5. paket.
    assert_eq!(st.chunks().next().unwrap().first_pkt, 5);
}

#[test]
fn late_hole_fill_is_retransmission() {
    let mut cap = Cap::new();
    handshake(&mut cap, c(), s(), CISN, SISN);
    cap.tcp(c(), s(), &Tcp::new(CISN + 6, SISN + 1, ACK, b"world"));
    cap.step_ms = 200;
    let p = cap.tcp(c(), s(), &Tcp::new(CISN + 1, SISN + 1, ACK, b"hello"));
    assert_eq!(flags(&p), [A::Retransmission]);
    assert_eq!(
        cap.table.stream(tcp0()).unwrap().data(Dir::Client),
        b"helloworld"
    );
}

#[test]
fn retransmission_not_duplicated() {
    let mut cap = Cap::new();
    handshake(&mut cap, c(), s(), CISN, SISN);
    cap.tcp(c(), s(), &Tcp::new(CISN + 1, SISN + 1, ACK, b"hello"));
    let p = cap.tcp(c(), s(), &Tcp::new(CISN + 1, SISN + 1, ACK, b"hello"));
    assert_eq!(flags(&p), [A::Retransmission]);
    assert_eq!(
        cap.table.stream(tcp0()).unwrap().data(Dir::Client),
        b"hello"
    );
}

#[test]
fn spurious_retransmission_after_ack() {
    let mut cap = Cap::new();
    handshake(&mut cap, c(), s(), CISN, SISN);
    cap.tcp(c(), s(), &Tcp::new(CISN + 1, SISN + 1, ACK, b"hello"));
    cap.tcp(s(), c(), &Tcp::new(SISN + 1, CISN + 6, ACK, &[]));
    let p = cap.tcp(c(), s(), &Tcp::new(CISN + 1, SISN + 1, ACK, b"hello"));
    assert_eq!(flags(&p), [A::SpuriousRetransmission]);
}

#[test]
fn syn_retransmission() {
    let mut cap = Cap::new();
    cap.tcp(c(), s(), &Tcp::new(CISN, 0, SYN, &[]));
    let p = cap.tcp(c(), s(), &Tcp::new(CISN, 0, SYN, &[]));
    assert_eq!(flags(&p), [A::Retransmission]);
    assert_eq!(cap.table.len(), 1);
}

#[test]
fn partial_overlap_first_wins() {
    let mut cap = Cap::new();
    handshake(&mut cap, c(), s(), CISN, SISN);
    cap.step_ms = 1;
    // [5,10) önce gelir, sonra [0,8) örtüşerek gelir: 5..8 ilk gelenden kalır.
    cap.tcp(c(), s(), &Tcp::new(CISN + 6, SISN + 1, ACK, b"FGHIJ"));
    let p = cap.tcp(c(), s(), &Tcp::new(CISN + 1, SISN + 1, ACK, b"abcdexyz"));
    assert_eq!(flags(&p), [A::OutOfOrder]);
    // [8,14) teslim edilmiş bölgeyle örtüşür: yalnızca 10..14 eklenir.
    cap.step_ms = 10;
    let p = cap.tcp(c(), s(), &Tcp::new(CISN + 9, SISN + 1, ACK, b"qqKLMN"));
    assert_eq!(flags(&p), [A::Retransmission]);
    assert_eq!(
        cap.table.stream(tcp0()).unwrap().data(Dir::Client),
        b"abcdeFGHIJKLMN"
    );
}

#[test]
fn lost_segment_marked_on_close() {
    let mut cap = Cap::new();
    handshake(&mut cap, c(), s(), CISN, SISN);
    cap.tcp(c(), s(), &Tcp::new(CISN + 1, SISN + 1, ACK, b"aaaa"));
    // CISN+5..CISN+9 kayıp.
    let p = cap.tcp(c(), s(), &Tcp::new(CISN + 9, SISN + 1, ACK, b"cccc"));
    assert_eq!(flags(&p), [A::PreviousSegmentNotCaptured]);
    let p = cap.tcp(s(), c(), &Tcp::new(SISN + 1, CISN + 13, ACK, &[]));
    assert_eq!(flags(&p), [] as [A; 0]);
    cap.tcp(c(), s(), &Tcp::new(CISN + 13, SISN + 1, FIN | ACK, &[]));
    cap.tcp(s(), c(), &Tcp::new(SISN + 1, CISN + 14, FIN | ACK, &[]));
    let ch: Vec<_> = cap.table.stream(tcp0()).unwrap().chunks().collect();
    assert_eq!(ch.len(), 3);
    assert_eq!(ch[1].marker, Some(Marker::Lost(4)));
    assert_eq!(render_ascii(&ch[1]), "[4 bayt eksik]");
    assert_eq!(ch[2].data, b"cccc");
}

#[test]
fn gap_threshold_skips_without_close() {
    let cfg = Config {
        gap_threshold: 8,
        ..Config::default()
    };
    let mut cap = Cap::with(FlowTable::with_config(cfg).unwrap());
    handshake(&mut cap, c(), s(), CISN, SISN);
    cap.tcp(c(), s(), &Tcp::new(CISN + 11, SISN + 1, ACK, b"12345"));
    assert!(cap
        .table
        .stream(tcp0())
        .unwrap()
        .data(Dir::Client)
        .is_empty());
    cap.tcp(c(), s(), &Tcp::new(CISN + 16, SISN + 1, ACK, b"6789"));
    let st = cap.table.stream(tcp0()).unwrap();
    assert_eq!(st.data(Dir::Client), b"123456789");
    assert_eq!(st.chunks().next().unwrap().marker, Some(Marker::Lost(10)));
}

#[test]
fn ack_of_unseen_segment() {
    let mut cap = Cap::new();
    handshake(&mut cap, c(), s(), CISN, SISN);
    cap.tcp(c(), s(), &Tcp::new(CISN + 1, SISN + 1, ACK, b"aaaa"));
    let p = cap.tcp(s(), c(), &Tcp::new(SISN + 1, CISN + 50, ACK, &[]));
    assert_eq!(flags(&p), [A::AckedUnseenSegment]);
}

#[test]
fn sequence_wraparound() {
    let isn = 0xFFFF_FF00;
    let mut cap = Cap::new();
    handshake(&mut cap, c(), s(), isn, SISN);
    cap.step_ms = 1;
    let data: Vec<u8> = (0..600u32)
        .map(|i| u8::try_from(i % 251).unwrap())
        .collect();
    let seg = |i: usize| {
        Tcp::new(
            isn.wrapping_add(1 + u32::try_from(i * 200).unwrap()),
            SISN + 1,
            ACK,
            &data[i * 200..(i + 1) * 200],
        )
    };
    let p = cap.tcp(c(), s(), &seg(0));
    assert_eq!(p.tcp.unwrap().rel_seq, 1);
    let p = cap.tcp(c(), s(), &seg(2));
    assert_eq!(p.tcp.as_ref().unwrap().rel_seq, 401);
    assert_eq!(flags(&p), [A::PreviousSegmentNotCaptured]);
    let p = cap.tcp(c(), s(), &seg(1));
    assert_eq!(p.tcp.as_ref().unwrap().rel_seq, 201);
    assert_eq!(flags(&p), [A::OutOfOrder]);
    // Sarmalamadan sonraki ACK: göreli 601.
    let p = cap.tcp(
        s(),
        c(),
        &Tcp::new(SISN + 1, isn.wrapping_add(601), ACK, &[]),
    );
    assert_eq!(p.tcp.as_ref().unwrap().rel_ack, Some(601));
    assert!(flags(&p).is_empty());
    assert_eq!(cap.table.stream(tcp0()).unwrap().data(Dir::Client), data);
}

#[test]
fn dup_acks_then_fast_retransmission() {
    let mut cap = Cap::new();
    handshake(&mut cap, c(), s(), CISN, SISN);
    let seg = |i: u32| {
        Tcp::new(
            CISN + 1 + i * 10,
            SISN + 1,
            ACK,
            &[b'a' + u8::try_from(i).unwrap(); 10],
        )
    };
    cap.tcp(c(), s(), &seg(0));
    cap.tcp(s(), c(), &Tcp::new(SISN + 1, CISN + 11, ACK, &[]));
    // seg(1) kayıp; 2,3,4 gelir ve her biri dup ACK üretir.
    for i in 2..=4 {
        let p = cap.tcp(c(), s(), &seg(i));
        if i == 2 {
            assert_eq!(flags(&p), [A::PreviousSegmentNotCaptured]);
        }
        let p = cap.tcp(s(), c(), &Tcp::new(SISN + 1, CISN + 11, ACK, &[]));
        assert_eq!(flags(&p), [A::DuplicateAck(i - 1)]);
    }
    let p = cap.tcp(c(), s(), &seg(1));
    assert_eq!(flags(&p), [A::FastRetransmission]);
    let p = cap.tcp(s(), c(), &Tcp::new(SISN + 1, CISN + 51, ACK, &[]));
    assert!(flags(&p).is_empty());
    assert_eq!(
        cap.table.stream(tcp0()).unwrap().data(Dir::Client),
        b"aaaaaaaaaabbbbbbbbbbccccccccccddddddddddeeeeeeeeee"
    );
}

#[test]
fn zero_window_and_probe() {
    let mut cap = Cap::new();
    handshake(&mut cap, c(), s(), CISN, SISN);
    cap.tcp(c(), s(), &Tcp::new(CISN + 1, SISN + 1, ACK, b"abcd"));
    let p = cap.tcp(s(), c(), &Tcp::new(SISN + 1, CISN + 5, ACK, &[]).win(0));
    assert_eq!(flags(&p), [A::ZeroWindow]);
    assert_eq!(p.tcp.unwrap().window, 0);
    let p = cap.tcp(c(), s(), &Tcp::new(CISN + 5, SISN + 1, ACK, b"e"));
    assert_eq!(flags(&p), [A::ZeroWindowProbe]);
}

#[test]
fn window_full() {
    let mut cap = Cap::new();
    handshake(&mut cap, c(), s(), CISN, SISN);
    cap.tcp(s(), c(), &Tcp::new(SISN + 1, CISN + 1, ACK, &[]).win(10));
    let p = cap.tcp(c(), s(), &Tcp::new(CISN + 1, SISN + 1, ACK, b"0123456789"));
    assert_eq!(flags(&p), [A::WindowFull]);
}

#[test]
fn window_scaling_applied() {
    let mut cap = Cap::new();
    let p = cap.tcp(c(), s(), &Tcp::new(CISN, 0, SYN, &[]).ws(7).win(100));
    assert_eq!(p.tcp.unwrap().window, 100, "SYN ölçeklenmez");
    cap.tcp(s(), c(), &Tcp::new(SISN, CISN + 1, SYN | ACK, &[]).ws(2));
    let p = cap.tcp(c(), s(), &Tcp::new(CISN + 1, SISN + 1, ACK, &[]).win(100));
    assert_eq!(p.tcp.unwrap().window, 12_800);
    let p = cap.tcp(s(), c(), &Tcp::new(SISN + 1, CISN + 1, ACK, b"x").win(100));
    assert_eq!(p.tcp.unwrap().window, 400);
}

#[test]
fn window_scaling_needs_both_sides() {
    let mut cap = Cap::new();
    cap.tcp(c(), s(), &Tcp::new(CISN, 0, SYN, &[]).ws(7));
    cap.tcp(s(), c(), &Tcp::new(SISN, CISN + 1, SYN | ACK, &[]));
    let p = cap.tcp(c(), s(), &Tcp::new(CISN + 1, SISN + 1, ACK, &[]).win(100));
    assert_eq!(p.tcp.unwrap().window, 100);
}

#[test]
fn rst_resets_and_new_syn_opens_new_stream() {
    let mut cap = Cap::new();
    handshake(&mut cap, c(), s(), CISN, SISN);
    let p = cap.tcp(s(), c(), &Tcp::new(SISN + 1, CISN + 1, RST | ACK, &[]));
    assert_eq!(flags(&p), [A::Rst]);
    assert_eq!(cap.table.conversations()[0].state, Some(TcpState::Reset));
    let p = cap.tcp(c(), s(), &Tcp::new(9999, 0, SYN, &[]));
    assert_eq!(p.stream.index, 1);
    let conv = cap.table.conversations();
    assert_eq!(conv.len(), 2);
    assert_eq!(conv[1].state, Some(TcpState::SynSent));
}

#[test]
fn port_reuse_after_fin_close() {
    let mut cap = Cap::new();
    handshake(&mut cap, c(), s(), CISN, SISN);
    cap.tcp(c(), s(), &Tcp::new(CISN + 1, SISN + 1, FIN | ACK, &[]));
    cap.tcp(s(), c(), &Tcp::new(SISN + 1, CISN + 2, FIN | ACK, &[]));
    let p = cap.tcp(c(), s(), &Tcp::new(CISN + 2, SISN + 2, ACK, &[]));
    assert_eq!(p.stream.index, 0, "son ACK aynı akışa ait");
    let p = cap.tcp(c(), s(), &Tcp::new(123_456, 0, SYN, &[]));
    assert_eq!(p.stream.index, 1);
}

#[test]
fn keepalive() {
    let mut cap = Cap::new();
    handshake(&mut cap, c(), s(), CISN, SISN);
    cap.tcp(c(), s(), &Tcp::new(CISN + 1, SISN + 1, ACK, b"abc"));
    let p = cap.tcp(c(), s(), &Tcp::new(CISN + 3, SISN + 1, ACK, &[]));
    assert_eq!(flags(&p), [A::KeepAlive]);
    let p = cap.tcp(c(), s(), &Tcp::new(CISN + 3, SISN + 1, ACK, b"\0"));
    assert_eq!(flags(&p), [A::KeepAlive]);
    assert_eq!(cap.table.stream(tcp0()).unwrap().data(Dir::Client), b"abc");
}

#[test]
fn ipv6_flow() {
    let (cl, sv) = (sa("[2001:db8::1]:40000"), sa("[2001:db8::2]:443"));
    let mut cap = Cap::new();
    handshake(&mut cap, cl, sv, CISN, SISN);
    cap.tcp(cl, sv, &Tcp::new(CISN + 1, SISN + 1, ACK, b"GET"));
    let p = cap.tcp(sv, cl, &Tcp::new(SISN + 1, CISN + 4, ACK, b"OK"));
    assert_eq!(p.dir, Dir::Server);
    assert!(p.key.a.is_ipv6());
    assert_eq!(p.tcp.unwrap().rel_ack, Some(4));
    assert_eq!(
        chunks_text(&cap.table, tcp0()),
        [
            (Dir::Client, "GET".to_owned()),
            (Dir::Server, "OK".to_owned())
        ]
    );
}

#[test]
fn udp_conversation() {
    let mut cap = Cap::new();
    let (cl, sv) = (sa("10.0.0.1:5000"), sa("8.8.8.8:53"));
    let p = cap.udp(cl, sv, b"q1");
    let udp0 = StreamId {
        proto: Proto::Udp,
        index: 0,
    };
    assert_eq!(p.stream, udp0);
    assert!(p.tcp.is_none());
    cap.udp(cl, sv, b"q2");
    let p = cap.udp(sv, cl, b"answer");
    assert_eq!(p.dir, Dir::Server);
    // Başka uç → yeni udp akışı; TCP sayacı bağımsız.
    let p = cap.udp(cl, sa("1.1.1.1:53"), b"x");
    assert_eq!(p.stream.index, 1);
    let p = cap.tcp(c(), s(), &Tcp::new(1, 0, SYN, &[]));
    assert_eq!(p.stream, tcp0());

    let conv = cap.table.conversations();
    let u = conv.iter().find(|c| c.stream == udp0).unwrap();
    assert_eq!(u.packets, [2, 1]);
    // 14 + 20 + 8 + yük.
    assert_eq!(u.bytes, [88, 48]);
    assert_eq!(u.state, None);
    assert_eq!(u.duration, Duration::from_millis(20));
    let ch: Vec<_> = cap.table.stream(udp0).unwrap().chunks().collect();
    assert_eq!(ch.len(), 3, "datagramlar birleştirilmez");
    assert_eq!(ch[1].data, b"q2");
    assert_eq!(ch[1].first_pkt, 2);
    assert_eq!(ch[2].dir, Dir::Server);
}

#[test]
fn follow_chunks_split_by_direction() {
    let mut cap = Cap::new();
    handshake(&mut cap, c(), s(), CISN, SISN);
    cap.tcp(
        c(),
        s(),
        &Tcp::new(CISN + 1, SISN + 1, ACK, b"GET / HTTP/1.1\r\n"),
    );
    cap.tcp(c(), s(), &Tcp::new(CISN + 17, SISN + 1, ACK, b"\r\n"));
    cap.tcp(
        s(),
        c(),
        &Tcp::new(SISN + 1, CISN + 19, ACK, b"HTTP/1.1 200 OK\r\n"),
    );
    cap.tcp(s(), c(), &Tcp::new(SISN + 18, CISN + 19, ACK, b"\r\nbody"));
    cap.tcp(c(), s(), &Tcp::new(CISN + 19, SISN + 24, ACK, b"bye"));
    let st = cap.table.stream(tcp0()).unwrap();
    let ch: Vec<_> = st.chunks().collect();
    assert_eq!(ch.len(), 3);
    assert_eq!(
        ch.iter().map(|c| (c.dir, c.first_pkt)).collect::<Vec<_>>(),
        [(Dir::Client, 4), (Dir::Server, 6), (Dir::Client, 8)]
    );
    assert_eq!(render_ascii(&ch[0]), "GET / HTTP/1.1.\n.\n");
    // Uygulama katmanı kancası: yön başına birleşik bayt.
    assert_eq!(st.data(Dir::Server), b"HTTP/1.1 200 OK\r\n\r\nbody");
}

#[test]
fn memory_limit_per_direction() {
    let cfg = Config {
        max_buffer: 1000,
        gap_threshold: 500,
        ..Config::default()
    };
    let mut cap = Cap::with(FlowTable::with_config(cfg).unwrap());
    handshake(&mut cap, c(), s(), CISN, SISN);
    for i in 0..3u32 {
        let d = [b'0' + u8::try_from(i).unwrap(); 1000];
        cap.tcp(c(), s(), &Tcp::new(CISN + 1 + i * 1000, SISN + 1, ACK, &d));
    }
    cap.tcp(s(), c(), &Tcp::new(SISN + 1, CISN + 3001, ACK, b"ok"));
    let st = cap.table.stream(tcp0()).unwrap();
    assert_eq!(st.stored_bytes(Dir::Client), 1000);
    assert_eq!(st.dropped_bytes(Dir::Client), 2000);
    assert_eq!(st.data(Dir::Client), [b'2'; 1000]);
    assert_eq!(st.data(Dir::Server), b"ok");
    let first = st.chunks().next().unwrap();
    assert_eq!(first.marker, Some(Marker::Dropped(2000)));
}

#[test]
fn lru_eviction() {
    let cfg = Config {
        max_flows: 2,
        ..Config::default()
    };
    let mut cap = Cap::with(FlowTable::with_config(cfg).unwrap());
    let a = cap.udp(sa("10.0.0.1:1"), sa("10.0.0.9:9"), b"a").stream;
    let b = cap.udp(sa("10.0.0.2:1"), sa("10.0.0.9:9"), b"b").stream;
    // a'ya dokun → en eski b olur.
    cap.udp(sa("10.0.0.1:1"), sa("10.0.0.9:9"), b"a2");
    let c3 = cap.udp(sa("10.0.0.3:1"), sa("10.0.0.9:9"), b"c").stream;
    assert_eq!(cap.table.len(), 2);
    assert_eq!(cap.table.evicted(), 1);
    assert!(cap.table.stream(b).is_none());
    assert!(cap.table.stream(a).is_some());
    assert!(cap.table.stream(c3).is_some());
    // Atılan anahtar yeniden görülürse yeni id alır.
    let b2 = cap.udp(sa("10.0.0.2:1"), sa("10.0.0.9:9"), b"b").stream;
    assert_eq!(b2.index, 3);
}

#[test]
fn idle_timeout_evicts() {
    let cfg = Config {
        idle_timeout: Some(Duration::from_secs(1)),
        ..Config::default()
    };
    let mut cap = Cap::with(FlowTable::with_config(cfg).unwrap());
    let a = cap.udp(sa("10.0.0.1:1"), sa("10.0.0.9:9"), b"a").stream;
    cap.step_ms = 500;
    let b = cap.udp(sa("10.0.0.2:1"), sa("10.0.0.9:9"), b"b").stream;
    assert_eq!(cap.table.len(), 2);
    cap.step_ms = 800;
    cap.udp(sa("10.0.0.2:1"), sa("10.0.0.9:9"), b"b");
    assert!(cap.table.stream(a).is_none(), "1.3 s boşta");
    assert!(cap.table.stream(b).is_some());
}

#[test]
fn non_transport_packets_ignored() {
    let mut cap = Cap::new();
    // ARP isteği.
    let arp: Vec<u8> = [
        &[0xff; 6][..],
        &[2, 0, 0, 0, 0, 1],
        &[0x08, 0x06, 0, 1, 0x08, 0, 6, 4, 0, 1],
        &[2, 0, 0, 0, 0, 1, 10, 0, 0, 1],
        &[0; 6],
        &[10, 0, 0, 2],
    ]
    .concat();
    assert!(cap.frame(arp).is_none());
    assert!(cap.frame(vec![1, 2, 3]).is_none());
    assert!(cap.table.is_empty());
}

#[test]
fn conversations_summary() {
    let mut cap = Cap::new();
    handshake(&mut cap, c(), s(), CISN, SISN);
    cap.tcp(c(), s(), &Tcp::new(CISN + 1, SISN + 1, ACK, b"12345"));
    let (c2, s2) = (sa("10.0.0.3:40001"), sa("10.0.0.4:22"));
    cap.tcp(c2, s2, &Tcp::new(1, 0, SYN, &[]));
    let conv = cap.table.conversations();
    assert_eq!(conv.len(), 2);
    assert_eq!(conv[0].stream.index, 0);
    assert_eq!(conv[1].stream.index, 1);
    // Ethernet 14 + IPv4 20 + TCP 20 = 54 bayt başlık.
    assert_eq!(conv[0].packets, [3, 1]);
    assert_eq!(conv[0].bytes, [54 * 3 + 5, 54]);
    assert_eq!(conv[0].duration, Duration::from_millis(30));
    assert_eq!(conv[1].state, Some(TcpState::SynSent));
}

#[test]
fn flush_all_delivers_pending() {
    let mut cap = Cap::new();
    handshake(&mut cap, c(), s(), CISN, SISN);
    cap.tcp(c(), s(), &Tcp::new(CISN + 4, SISN + 1, ACK, b"def"));
    assert!(cap
        .table
        .stream(tcp0())
        .unwrap()
        .data(Dir::Client)
        .is_empty());
    cap.table.flush_all();
    let st = cap.table.stream(tcp0()).unwrap();
    assert_eq!(st.data(Dir::Client), b"def");
    assert_eq!(st.chunks().next().unwrap().marker, Some(Marker::Lost(3)));
}

/// Rastgele boyutlu segmentler, rastgele permütasyon + rastgele yinelemeler:
/// birleşik veri her zaman özgün veriye eşit olmalı.
#[test]
fn random_permutations_reassemble_identically() {
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    for trial in 0..40u32 {
        let total = 200 + rng.below(3000);
        let data: Vec<u8> = (0..total)
            .map(|_| u8::try_from(rng.next() & 0xff).unwrap())
            .collect();
        let isn = if trial % 2 == 0 {
            u32::try_from(rng.next() & 0xffff_ffff).unwrap()
        } else {
            0xFFFF_FF00
        };
        let mut segs = Vec::new();
        let mut off = 0;
        while off < total {
            let n = (1 + rng.below(300)).min(total - off);
            segs.push((off, n));
            off += n;
        }
        // Birkaç yineleme ve örtüşen parça ekle.
        for _ in 0..rng.below(5) {
            let (o, n) = segs[rng.below(segs.len())];
            let cut = rng.below(n);
            segs.push((o + cut, n - cut));
        }
        rng.shuffle(&mut segs);

        let mut cap = Cap::new();
        cap.step_ms = 1;
        handshake(&mut cap, c(), s(), isn, SISN);
        for (o, n) in segs {
            let seq = isn.wrapping_add(1).wrapping_add(u32::try_from(o).unwrap());
            cap.tcp(c(), s(), &Tcp::new(seq, SISN + 1, ACK, &data[o..o + n]));
        }
        let fin = isn
            .wrapping_add(1)
            .wrapping_add(u32::try_from(total).unwrap());
        cap.tcp(c(), s(), &Tcp::new(fin, SISN + 1, FIN | ACK, &[]));
        cap.tcp(
            s(),
            c(),
            &Tcp::new(SISN + 1, fin.wrapping_add(1), FIN | ACK, &[]),
        );
        let st = cap.table.stream(tcp0()).unwrap();
        assert_eq!(st.data(Dir::Client), data, "deneme {trial}");
        assert!(st.chunks().all(|c| c.marker.is_none()), "deneme {trial}");
        assert_eq!(cap.table.conversations()[0].state, Some(TcpState::Closed));
    }
}
