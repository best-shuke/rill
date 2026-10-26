use super::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

async fn pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (connect, accept) = tokio::join!(
        TcpStream::connect(listener.local_addr().unwrap()),
        listener.accept()
    );
    (connect.unwrap(), accept.unwrap().0)
}

async fn exchange(mut socket: TcpStream, send: u8, receive: u8, total: usize) {
    let (mut reader, mut writer) = socket.split();
    let send = async {
        let data: Vec<u8> = (0..RELAY_BULK_BUF_SIZE)
            .map(|i| (i as u8).wrapping_add(send))
            .collect();
        for _ in 0..total / data.len() {
            writer.write_all(&data).await.unwrap();
        }
        writer.shutdown().await.unwrap();
    };
    let receive = async {
        let mut data = vec![0; RELAY_BULK_BUF_SIZE];
        let mut offset = 0;
        loop {
            let n = reader.read(&mut data).await.unwrap();
            if n == 0 {
                break;
            }
            for (i, byte) in data[..n].iter().enumerate() {
                assert_eq!(*byte, ((offset + i) as u8).wrapping_add(receive));
            }
            offset += n;
        }
        assert_eq!(offset, total);
    };
    tokio::join!(send, receive);
}

#[tokio::test]
async fn splice_bulk_bidirectional_correctness_and_exact_stats() {
    const TOTAL: usize = 64 * 1024 * 1024;
    let (client, mut a) = pair().await;
    let (mut b, upstream) = pair().await;
    splice::SPLICED_BYTES.with(|bytes| bytes.set(0));
    tokio::time::timeout(Duration::from_secs(60), async {
        let relay = async {
            let mut upload = 0;
            let mut download = 0;
            let counts = copy_bidirectional_tracked(
                &mut a,
                &mut b,
                |s| Some(s),
                |s| Some(s),
                |n| upload += n,
                |n| download += n,
            )
            .await
            .unwrap();
            assert_eq!(counts, (TOTAL as u64, TOTAL as u64));
            assert_eq!(counts, (upload, download));
        };
        tokio::join!(
            relay,
            exchange(client, 7, 19, TOTAL),
            exchange(upstream, 19, 7, TOTAL)
        );
    })
    .await
    .expect("bulk relay stalled");
    let spliced = splice::SPLICED_BYTES.with(std::cell::Cell::get);
    assert!(spliced <= 2 * (TOTAL as u64 - RELAY_BULK_UPGRADE_BYTES));
    assert!(spliced >= 2 * (TOTAL as u64 - RELAY_BULK_UPGRADE_BYTES - RELAY_BUF_SIZE as u64));
}

async fn half_close(reverse: bool) {
    let (mut client, mut a) = pair().await;
    let (mut b, mut upstream) = pair().await;
    if reverse {
        std::mem::swap(&mut client, &mut upstream);
    }
    let payload = vec![37; RELAY_BULK_UPGRADE_BYTES as usize * 3];
    tokio::time::timeout(Duration::from_secs(10), async {
        let relay =
            copy_bidirectional_tracked(&mut a, &mut b, |s| Some(s), |s| Some(s), |_| {}, |_| {});
        let sender = async {
            client.write_all(&payload).await.unwrap();
            client.shutdown().await.unwrap();
            let mut response = Vec::new();
            client.read_to_end(&mut response).await.unwrap();
            assert_eq!(response, payload);
        };
        let responder = async {
            let mut request = Vec::new();
            upstream.read_to_end(&mut request).await.unwrap();
            assert_eq!(request, payload, "EOF must follow the last piped byte");
            upstream.write_all(&request).await.unwrap();
            upstream.shutdown().await.unwrap();
        };
        let (counts, (), ()) = tokio::join!(relay, sender, responder);
        assert_eq!(
            counts.unwrap(),
            (payload.len() as u64, payload.len() as u64)
        );
    })
    .await
    .expect("half-close stalled");
}

#[tokio::test]
async fn splice_client_half_close_drains_before_shutdown() {
    half_close(false).await;
}

#[tokio::test]
async fn splice_upstream_half_close_drains_before_shutdown() {
    half_close(true).await;
}

#[tokio::test]
async fn splice_peer_reset_is_an_error() {
    use std::os::fd::AsRawFd;
    let (mut client, mut a) = pair().await;
    let (mut b, mut upstream) = pair().await;
    splice::SPLICED_BYTES.with(|bytes| bytes.set(0));
    tokio::time::timeout(Duration::from_secs(10), async {
        let relay = async {
            let result = copy_bidirectional_tracked(
                &mut a,
                &mut b,
                |s| Some(s),
                |s| Some(s),
                |_| {},
                |_| {},
            )
            .await;
            drop((a, b));
            result
        };
        let sender = async {
            let data = vec![1; 8 * 1024 * 1024];
            let _ = client.write_all(&data).await;
        };
        let reset = async {
            upstream
                .read_exact(&mut vec![0; RELAY_BULK_UPGRADE_BYTES as usize * 2])
                .await
                .unwrap();
            assert!(splice::SPLICED_BYTES.with(std::cell::Cell::get) > 0);
            let linger = libc::linger {
                l_onoff: 1,
                l_linger: 0,
            };
            // SAFETY: upstream owns a live socket; linger has the required layout.
            assert_eq!(
                unsafe {
                    libc::setsockopt(
                        upstream.as_raw_fd(),
                        libc::SOL_SOCKET,
                        libc::SO_LINGER,
                        (&raw const linger).cast(),
                        std::mem::size_of_val(&linger) as libc::socklen_t,
                    )
                },
                0
            );
            drop(upstream);
        };
        let (result, (), ()) = tokio::join!(relay, sender, reset);
        let e = result.unwrap_err();
        assert!(
            matches!(
                e.kind(),
                io::ErrorKind::ConnectionReset
                    | io::ErrorKind::BrokenPipe
                    | io::ErrorKind::ConnectionAborted
            ),
            "{e}"
        );
    })
    .await
    .expect("reset relay stalled");
}

#[tokio::test]
async fn non_tcp_endpoint_stays_on_copy_path() {
    let (client, mut a) = pair().await;
    let (mut b, mut upstream) = tokio::io::duplex(1024);
    let total = RELAY_BULK_UPGRADE_BYTES as usize * 3;
    splice::SPLICED_BYTES.with(|bytes| bytes.set(0));
    splice::LAST_PIPE.with(|pipe| pipe.set(None));
    tokio::time::timeout(Duration::from_secs(10), async {
        let relay =
            copy_bidirectional_tracked(&mut a, &mut b, |s| Some(s), |_| None, |_| {}, |_| {});
        let client = exchange(client, 5, 11, total);
        let upstream = async {
            let (mut r, mut w) = tokio::io::split(&mut upstream);
            let send = async {
                let bytes: Vec<u8> = (0..total).map(|i| (i as u8).wrapping_add(11)).collect();
                w.write_all(&bytes).await.unwrap();
                w.shutdown().await.unwrap();
            };
            let receive = async {
                let mut bytes = Vec::new();
                r.read_to_end(&mut bytes).await.unwrap();
                assert_eq!(bytes.len(), total);
                for (i, byte) in bytes.iter().enumerate() {
                    assert_eq!(*byte, (i as u8).wrapping_add(5));
                }
            };
            tokio::join!(send, receive);
        };
        let (counts, (), ()) = tokio::join!(relay, client, upstream);
        assert_eq!(counts.unwrap(), (total as u64, total as u64));
    })
    .await
    .unwrap();
    assert_eq!(splice::SPLICED_BYTES.with(std::cell::Cell::get), 0);
    assert!(splice::LAST_PIPE.with(std::cell::Cell::get).is_none());
}

#[tokio::test]
async fn unsupported_destination_splice_recovers_buffered_pipe_bytes() {
    let (mut client, mut src) = pair().await;
    let (mut dst, mut upstream) = pair().await;
    let payload = vec![83; RELAY_BULK_BUF_SIZE * 3];
    client.write_all(&payload).await.unwrap();
    client.shutdown().await.unwrap();
    let mut half = HalfCopy::new();
    half.amt = RELAY_BULK_UPGRADE_BYTES;
    let mut pipe = splice::Pipe::new().unwrap();
    pipe.reject_write = true;
    half.pipe = Some(pipe);
    let mut allow = true;
    let mut delivered = 0;
    tokio::time::timeout(
        Duration::from_secs(10),
        poll_fn(|cx| loop {
            match half.poll_cycle(
                cx,
                Pin::new(&mut src),
                Pin::new(&mut dst),
                (|s| Some(s), |s| Some(s)),
                &mut allow,
                &mut |n| delivered += n,
            )? {
                Cycle::Done => return Poll::Ready(Ok::<_, io::Error>(())),
                Cycle::Progress => {}
                Cycle::Pending => return Poll::Pending,
            }
        }),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(
        !allow,
        "unsupported splice disables both relay directions permanently"
    );
    assert!(half.pipe.is_none());
    assert_eq!(delivered, payload.len() as u64);
    let mut received = Vec::new();
    upstream.read_to_end(&mut received).await.unwrap();
    assert_eq!(received, payload);
}

#[tokio::test]
async fn pipes_are_lazy_until_the_bulk_threshold() {
    let (mut client, mut src) = pair().await;
    let (mut dst, _upstream) = pair().await;
    let mut half = HalfCopy::new();
    let mut allow = true;
    half.amt = RELAY_BULK_UPGRADE_BYTES - 1;
    poll_fn(|cx| {
        assert!(matches!(
            half.poll_cycle(
                cx,
                Pin::new(&mut src),
                Pin::new(&mut dst),
                (|s| Some(s), |s| Some(s)),
                &mut allow,
                &mut |_| {}
            )
            .unwrap(),
            Cycle::Pending
        ));
        Poll::Ready(())
    })
    .await;
    assert!(half.pipe.is_none(), "short connections create no pipes");
    half.amt = RELAY_BULK_UPGRADE_BYTES;
    client.write_all(b"bulk").await.unwrap();
    poll_fn(|cx| {
        match half
            .poll_cycle(
                cx,
                Pin::new(&mut src),
                Pin::new(&mut dst),
                (|s| Some(s), |s| Some(s)),
                &mut allow,
                &mut |_| {},
            )
            .unwrap()
        {
            Cycle::Progress => Poll::Ready(()),
            _ => Poll::Pending,
        }
    })
    .await;
    assert!(half.pipe.is_some());
    assert!(half.spill.is_none());
}

#[tokio::test]
async fn cancelling_relay_closes_its_splice_pipe() {
    let (mut client, mut a) = pair().await;
    let (mut b, _upstream) = pair().await;
    client
        .write_all(&vec![1; RELAY_BULK_UPGRADE_BYTES as usize * 2])
        .await
        .unwrap();
    splice::LAST_PIPE.with(|pipe| pipe.set(None));
    let mut relay = Box::pin(copy_bidirectional_tracked(
        &mut a,
        &mut b,
        |s| Some(s),
        |s| Some(s),
        |_| {},
        |_| {},
    ));
    let (read, write) = tokio::time::timeout(
        Duration::from_secs(10),
        poll_fn(|cx| {
            assert!(relay.as_mut().poll(cx).is_pending());
            match splice::LAST_PIPE.with(std::cell::Cell::get) {
                Some(fds) => Poll::Ready(fds),
                None => Poll::Pending,
            }
        }),
    )
    .await
    .unwrap();
    let target = std::fs::read_link(format!("/proc/self/fd/{read}")).unwrap();
    drop(relay);
    for fd in [read, write] {
        assert!(
            std::fs::read_link(format!("/proc/self/fd/{fd}")).map_or(true, |path| path != target)
        );
    }
}

#[test]
fn unsupported_errors_are_distinct_from_connection_failures() {
    for code in [libc::EINVAL, libc::ENOSYS, libc::EOPNOTSUPP] {
        assert!(splice::unsupported(&io::Error::from_raw_os_error(code)));
    }
    for code in [libc::ECONNRESET, libc::EPIPE, libc::EBADF] {
        assert!(!splice::unsupported(&io::Error::from_raw_os_error(code)));
    }
}
