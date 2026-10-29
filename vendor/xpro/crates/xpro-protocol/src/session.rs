use crate::{invalid, Frame, Kind, MAX_DATA};
use std::future::Future;
use std::{
    io,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf},
    sync::Notify,
    task::JoinHandle,
};
pub const QUEUE_BYTES: usize = 256 * 1024;
type Failure = Arc<Mutex<Option<(io::ErrorKind, String)>>>;
/// A bounded TCP-like stream. Dropping it cancels both frame pumps.
struct Progress {
    sent: std::sync::atomic::AtomicU64,
    waker: futures_util::task::AtomicWaker,
}
pub struct Session {
    io: DuplexStream,
    failure: Failure,
    task: JoinHandle<()>,
    shutdown: tokio::sync::oneshot::Receiver<()>,
    shutdown_done: bool,
    task_done: bool,
    written: u64,
    progress: Arc<Progress>,
}
impl Drop for Session {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl Session {
    pub async fn finish(&mut self) -> io::Result<()> {
        if !self.task_done {
            (&mut self.task).await.map_err(io::Error::other)?;
            self.task_done = true;
        }
        self.check()
    }
    fn check(&self) -> io::Result<()> {
        match self.failure.lock().unwrap().as_ref() {
            Some((k, s)) => Err(io::Error::new(*k, s.clone())),
            None => Ok(()),
        }
    }
}
impl AsyncRead for Session {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.check()?;
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        let before = buf.filled().len();
        let result = Pin::new(&mut self.io).poll_read(cx, buf);
        if matches!(result, Poll::Ready(Ok(())))
            && buf.filled().len() == before
            && self.shutdown_done
            && !self.task_done
        {
            std::task::ready!(Pin::new(&mut self.task).poll(cx)).map_err(io::Error::other)?;
            self.task_done = true;
        }
        if result.is_ready() {
            self.check()?;
        }
        result
    }
}
impl AsyncWrite for Session {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.check()?;
        let n = std::task::ready!(Pin::new(&mut self.io).poll_write(cx, buf))?;
        self.written = self
            .written
            .checked_add(n as u64)
            .ok_or_else(|| invalid("session byte counter overflow"))?;
        Poll::Ready(Ok(n))
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.progress.waker.register(cx.waker());
        self.check()?;
        if self
            .progress
            .sent
            .load(std::sync::atomic::Ordering::Acquire)
            >= self.written
        {
            Poll::Ready(Ok(()))
        } else {
            Poll::Pending
        }
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.check()?;
        if self.shutdown_done {
            return Poll::Ready(Ok(()));
        }
        std::task::ready!(Pin::new(&mut self.io).poll_shutdown(cx))?;
        match std::task::ready!(Pin::new(&mut self.shutdown).poll(cx)) {
            Ok(()) => {
                self.shutdown_done = true;
                Poll::Ready(Ok(()))
            }
            Err(_) => Poll::Ready(Err(crate::invalid(
                "session ended before HALF_CLOSE was sent",
            ))),
        }
    }
}
pub fn session<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(wire: S) -> Session {
    session_cancellable(wire, std::future::pending())
}
pub fn session_cancellable<S, F>(wire: S, stop: F) -> Session
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    F: Future<Output = ()> + Send + 'static,
{
    let (app, mut bridge) = tokio::io::duplex(QUEUE_BYTES);
    let failure: Failure = Arc::new(Mutex::new(None));
    let status = Arc::clone(&failure);
    let progress = Arc::new(Progress {
        sent: std::sync::atomic::AtomicU64::new(0),
        waker: futures_util::task::AtomicWaker::new(),
    });
    let track = Arc::clone(&progress);
    let (shutdown_tx, shutdown) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(async move {
        tokio::select! {
            _=stop=>{*status.lock().unwrap()=Some((io::ErrorKind::Interrupted,"session retired".into()));},
            _=pump(wire, &mut bridge, Arc::clone(&status), shutdown_tx,Arc::clone(&track))=>{}
        }
        track.waker.wake();
    });
    Session {
        io: app,
        failure,
        task,
        shutdown,
        shutdown_done: false,
        task_done: false,
        written: 0,
        progress,
    }
}
async fn pump<S: AsyncRead + AsyncWrite + Unpin>(
    wire: S,
    bridge: &mut DuplexStream,
    status: Failure,
    shutdown: tokio::sync::oneshot::Sender<()>,
    progress: Arc<Progress>,
) {
    // Keep ownership of the bridge here until the caller has recorded failure.
    let result: io::Result<()> = async {
        let (mut reader, mut writer) = tokio::io::split(wire);
        let (mut outgoing, mut incoming) = tokio::io::split(bridge);
        use std::sync::atomic::{AtomicBool, Ordering};
        let local = AtomicBool::new(false);
        let remote = AtomicBool::new(false);
        let notify = Notify::new();
        let closing = Notify::new();
        let send = async {
            let mut buf = vec![0; MAX_DATA];
            loop {
                let n = outgoing.read(&mut buf).await?;
                if n == 0 {
                    break;
                }
                Frame::new(Kind::Data, buf[..n].to_vec())
                    .write(&mut writer)
                    .await?;
                progress.sent.fetch_add(n as u64,Ordering::Release);progress.waker.wake();
            }
            Frame::new(Kind::HalfClose, vec![])
                .write(&mut writer)
                .await?;
            local.store(true, Ordering::Release);
            let _ = shutdown.send(());
            while !remote.load(Ordering::Acquire) {
                notify.notified().await;
            }
            Frame::new(Kind::Close, vec![]).write(&mut writer).await?;
            closing.notify_one();
            writer.shutdown().await
        };
        let receive = async {
            loop {
                let read=Frame::read(&mut reader);tokio::pin!(read);
                let wait_close=async {tokio::time::sleep(std::time::Duration::from_secs(5)).await;Err::<Frame,_>(io::Error::new(io::ErrorKind::TimedOut,"CLOSE timeout"))};
                let frame=if remote.load(Ordering::Acquire) && local.load(Ordering::Acquire) {
                    tokio::select!{f=&mut read=>f?,e=wait_close=>e?}
                }else{
                    tokio::select!{f=&mut read=>f?,_=closing.notified()=>{
                        tokio::time::timeout(std::time::Duration::from_secs(5),read).await.map_err(|_|io::Error::new(io::ErrorKind::TimedOut,"CLOSE timeout"))??
                    }}
                };
                match frame.kind {
                    Kind::Data if !remote.load(Ordering::Acquire) => {
                        incoming.write_all(&frame.payload).await?
                    }
                    Kind::HalfClose if !remote.swap(true, Ordering::AcqRel) => {
                        incoming.shutdown().await?;
                        notify.notify_one();
                    }
                    Kind::Close
                        if remote.load(Ordering::Acquire) && local.load(Ordering::Acquire) =>
                    {
                        return Ok(())
                    }
                    Kind::Error => return Err(invalid("authenticated remote error")),
                    _ => return Err(invalid("illegal established-session transition")),
                }
            }
        };
        tokio::try_join!(send, receive)?;
        Ok(())
    }
    .await;
    if let Err(e) = result {
        *status.lock().unwrap() = Some((e.kind(), e.to_string()));
    }
}
