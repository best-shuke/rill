use std::{cmp::min, io, net::SocketAddr, pin::Pin};

use futures::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc::{Sender, UnboundedReceiver, UnboundedSender};
use tokio_util::sync::PollSender;

use super::buffer::{Buffer, BufferPool};
use super::core::{Cmd, StreamCmd, StreamId, WRITE_CHUNK};

/// Pure-channel TCP stream handle. Never touches lwIP state: reads drain a
/// channel filled by `tcp_recv_cb` on the core task, writes travel a bounded
/// ordered channel the core drains into `tcp_write`, and dropping the handle
/// closes that channel — which *is* the close signal, so teardown can't be
/// lost. Fully `Send`; safe to poll from any runtime.
pub struct TcpStream {
    id: StreamId,
    src_addr: SocketAddr,
    dest_addr: SocketAddr,
    read_rx: UnboundedReceiver<Buffer>,
    /// Data pulled off `read_rx` that didn't fit the caller's buffer.
    leftover: Option<(Buffer, usize)>,
    /// EOF marker observed; subsequent reads return 0 bytes.
    eof: bool,
    write_pool: BufferPool,
    write_tx: PollSender<StreamCmd>,
    cmd_tx: UnboundedSender<Cmd>,
}

impl TcpStream {
    pub(crate) fn new(
        id: StreamId,
        src_addr: SocketAddr,
        dest_addr: SocketAddr,
        read_rx: UnboundedReceiver<Buffer>,
        write_tx: Sender<StreamCmd>,
        cmd_tx: UnboundedSender<Cmd>,
        write_pool: BufferPool,
    ) -> Self {
        TcpStream {
            id,
            src_addr,
            dest_addr,
            read_rx,
            leftover: None,
            eof: false,
            write_pool,
            write_tx: PollSender::new(write_tx),
            cmd_tx,
        }
    }

    pub fn local_addr(&self) -> &SocketAddr {
        &self.src_addr
    }

    pub fn remote_addr(&self) -> &SocketAddr {
        &self.dest_addr
    }
}

fn broken_pipe() -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, "broken pipe")
}

impl AsyncRead for TcpStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &mut ReadBuf,
    ) -> Poll<io::Result<()>> {
        let me = &mut *self;
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        if let Some((data, mut offset)) = me.leftover.take() {
            // Credit was sent when this buffer left the channel. Keep its
            // storage until the final byte is read, then return it to the pool.
            let n = min(buf.remaining(), data.len() - offset);
            buf.put_slice(&data[offset..offset + n]);
            offset += n;
            if offset < data.len() {
                me.leftover = Some((data, offset));
            }
            return Poll::Ready(Ok(()));
        }
        if me.eof {
            return Poll::Ready(Ok(()));
        }
        let mut has_read_data = false;
        loop {
            match me.read_rx.poll_recv(cx) {
                Poll::Ready(Some(data)) => {
                    if data.is_empty() {
                        // EOF marker from tcp_recv_cb.
                        me.eof = true;
                        return Poll::Ready(Ok(()));
                    }
                    // Open the receive window for what we consumed. Ignoring
                    // a send error is fine: the core being gone means the
                    // pcb is gone too.
                    let _ = me.cmd_tx.send(Cmd::Recved(me.id, data.len()));
                    let to_read = min(buf.remaining(), data.len());
                    buf.put_slice(&data[..to_read]);
                    has_read_data = true;
                    if to_read < data.len() {
                        me.leftover = Some((data, to_read));
                        return Poll::Ready(Ok(()));
                    }
                    if buf.remaining() == 0 {
                        return Poll::Ready(Ok(()));
                    }
                }
                // Channel closed without EOF: tcp_err_cb dropped the sender.
                Poll::Ready(None) => return Poll::Ready(Err(broken_pipe())),
                Poll::Pending => {
                    return if has_read_data {
                        Poll::Ready(Ok(()))
                    } else {
                        Poll::Pending
                    };
                }
            }
        }
    }
}

impl AsyncWrite for TcpStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let me = &mut *self;
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        match me.write_tx.poll_reserve(cx) {
            Poll::Ready(Ok(())) => {}
            // Receiver dropped: pcb errored or the core tore down.
            Poll::Ready(Err(_)) => return Poll::Ready(Err(broken_pipe())),
            Poll::Pending => return Poll::Pending,
        }
        let n = min(buf.len(), WRITE_CHUNK);
        let mut chunk = me.write_pool.take(n);
        chunk.extend_from_slice(&buf[..n]);
        if me.write_tx.send_item(StreamCmd::Write(chunk)).is_err() {
            return Poll::Ready(Err(broken_pipe()));
        }
        let _ = me.cmd_tx.send(Cmd::Kick(me.id));
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context) -> Poll<io::Result<()>> {
        // Data durability is guaranteed by ordering: queued writes are handed
        // to lwIP before any Shutdown/close is processed on the same channel,
        // and lwIP flushes its send buffer before FIN. tcp_output runs after
        // every core drain, so there is nothing to actively flush here.
        if self.write_tx.is_closed() {
            return Poll::Ready(Err(broken_pipe()));
        }
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        let me = &mut *self;
        match me.write_tx.poll_reserve(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(_)) => return Poll::Ready(Err(broken_pipe())),
            Poll::Pending => return Poll::Pending,
        }
        if me.write_tx.send_item(StreamCmd::Shutdown).is_err() {
            return Poll::Ready(Err(broken_pipe()));
        }
        let _ = me.cmd_tx.send(Cmd::Kick(me.id));
        Poll::Ready(Ok(()))
    }
}

impl Drop for TcpStream {
    fn drop(&mut self) {
        // Dropping write_tx closes the per-stream channel; the Kick makes the
        // core notice promptly (it doesn't select on per-stream channels).
        // The core drains queued writes first, then closes the pcb — abort if
        // no half-close was seen, graceful close otherwise.
        self.write_tx.close();
        let _ = self.cmd_tx.send(Cmd::Kick(self.id));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn partial_reads_keep_storage_and_eof_order() {
        let pool = BufferPool::new(4, 4 * WRITE_CHUNK, WRITE_CHUNK);
        let mut data = pool.take(6);
        data.extend_from_slice(b"abcdef");
        let ptr = data.as_ptr();
        let (read_tx, read_rx) = tokio::sync::mpsc::unbounded_channel();
        read_tx.send(data).unwrap();
        read_tx.send(pool.take(0)).unwrap();
        drop(read_tx);
        let (write_tx, _write_rx) = tokio::sync::mpsc::channel(1);
        let (cmd_tx, mut cmd_rx) = tokio::sync::mpsc::unbounded_channel();
        let addr = "127.0.0.1:80".parse().unwrap();
        let mut stream = TcpStream::new(1, addr, addr, read_rx, write_tx, cmd_tx, pool.clone());
        assert_eq!(stream.read(&mut []).await.unwrap(), 0);
        assert!(cmd_rx.try_recv().is_err());
        let mut first = [0; 2];
        stream.read_exact(&mut first).await.unwrap();
        assert_eq!(&first, b"ab");
        assert_eq!(stream.leftover.as_ref().unwrap().0.as_ptr(), ptr);
        assert!(matches!(cmd_rx.try_recv(), Ok(Cmd::Recved(1, 6))));
        let mut rest = Vec::new();
        stream.read_to_end(&mut rest).await.unwrap();
        assert_eq!(rest, b"cdef");
        assert!(
            cmd_rx.try_recv().is_err(),
            "leftovers must not credit twice"
        );
        assert_eq!(stream.read(&mut first).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn write_chunks_recycle_and_shutdown_stays_ordered() {
        let pool = BufferPool::new(2, 2 * WRITE_CHUNK, WRITE_CHUNK);
        let (_read_tx, read_rx) = tokio::sync::mpsc::unbounded_channel();
        let (write_tx, mut write_rx) = tokio::sync::mpsc::channel(1);
        let (cmd_tx, _cmd_rx) = tokio::sync::mpsc::unbounded_channel();
        let addr = "127.0.0.1:80".parse().unwrap();
        let mut stream = TcpStream::new(1, addr, addr, read_rx, write_tx, cmd_tx, pool);
        let payload = vec![0x5a; WRITE_CHUNK * 2];
        assert_eq!(stream.write(&payload).await.unwrap(), WRITE_CHUNK);
        let StreamCmd::Write(first) = write_rx.recv().await.unwrap() else {
            panic!("expected write");
        };
        let ptr = first.as_ptr();
        assert_eq!(&first[..], &payload[..WRITE_CHUNK]);
        drop(first);
        assert_eq!(stream.write(b"next").await.unwrap(), 4);
        let mut shutdown = Box::pin(stream.shutdown());
        assert!(
            futures::poll!(&mut shutdown).is_pending(),
            "full channel parks shutdown"
        );
        let StreamCmd::Write(second) = write_rx.recv().await.unwrap() else {
            panic!("expected write before shutdown");
        };
        assert_eq!(second.as_ptr(), ptr);
        assert_eq!(&second[..], b"next");
        shutdown.await.unwrap();
        assert!(matches!(
            write_rx.recv().await.unwrap(),
            StreamCmd::Shutdown
        ));
    }
}
