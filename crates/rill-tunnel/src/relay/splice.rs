//! Linux socket → pipe → socket transfer. Up to [`MAX_ENLARGED_PIPES`]
//! pipes at a time grow to 1 MiB, as Go's net package sizes its splice
//! pipes; the rest keep the default 64 KiB.
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{ready, Context, Poll};
use tokio::io::Interest;
use tokio::net::TcpStream;

#[cfg(test)]
thread_local! {
    pub(super) static LAST_PIPE: std::cell::Cell<Option<(RawFd, RawFd)>> = const { std::cell::Cell::new(None) };
    pub(super) static SPLICED_BYTES: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

/// Bytes one enlarged pipe holds, and so one splice call can move — as
/// Go's net package sizes its splice pipes. Against the 64 KiB default it
/// cut syscalls 16x and closed the bulk gap to mihomo (4 flows x 1 GiB
/// one-way through SOCKS5 on 4-core Neoverse-N1 loopback: 49.5 → 53.9
/// Gbps, mihomo 54.1).
const ENLARGED_PIPE_SIZE: libc::c_int = 1 << 20;
/// Pipes enlarged at once. Each counts its full size (256 pages) against the
/// per-user `pipe-user-pages-soft` quota (16 384 pages by default), past
/// which Linux shrinks every *new* pipe of the user to two pages — so the
/// enlarged ones stay within half of it, and the rest keep the default.
const MAX_ENLARGED_PIPES: usize = 32;
static ENLARGED_PIPES: AtomicUsize = AtomicUsize::new(0);

pub(super) struct Pipe {
    read: OwnedFd,
    write: OwnedFd,
    /// Holds one of the [`MAX_ENLARGED_PIPES`] slots.
    enlarged: bool,
    pub(super) buffered: usize,
    #[cfg(test)]
    pub(super) reject_write: bool,
}

impl Pipe {
    pub(super) fn new() -> io::Result<Self> {
        let mut fds = [-1; 2];
        // SAFETY: pipe2 initializes both descriptors on success.
        if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_NONBLOCK | libc::O_CLOEXEC) } < 0 {
            return Err(io::Error::last_os_error());
        }
        #[cfg(test)]
        LAST_PIPE.with(|pipe| pipe.set(Some((fds[0], fds[1]))));
        let enlarged = ENLARGED_PIPES.fetch_add(1, Ordering::Relaxed) < MAX_ENLARGED_PIPES
            // SAFETY: fds[1] is the pipe just created; F_SETPIPE_SZ takes an
            // int. Failure (EPERM past the quota, EBUSY) keeps the default.
            && unsafe { libc::fcntl(fds[1], libc::F_SETPIPE_SZ, ENLARGED_PIPE_SIZE) } >= 0;
        if !enlarged {
            ENLARGED_PIPES.fetch_sub(1, Ordering::Relaxed);
        }
        Ok(Self {
            // SAFETY: successful pipe2 returned two uniquely owned descriptors.
            read: unsafe { OwnedFd::from_raw_fd(fds[0]) },
            write: unsafe { OwnedFd::from_raw_fd(fds[1]) },
            enlarged,
            buffered: 0,
            #[cfg(test)]
            reject_write: false,
        })
    }

    pub(super) fn poll_fill(
        &mut self,
        cx: &mut Context<'_>,
        src: &TcpStream,
        limit: usize,
    ) -> Poll<io::Result<usize>> {
        debug_assert_eq!(self.buffered, 0);
        loop {
            ready!(src.poll_read_ready(cx))?;
            match src.try_io(Interest::READABLE, || {
                transfer(src.as_raw_fd(), self.write.as_raw_fd(), limit)
            }) {
                Ok(n) => {
                    self.buffered = n;
                    return Poll::Ready(Ok(n));
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                Err(e) => return Poll::Ready(Err(e)),
            }
        }
    }

    pub(super) fn poll_drain(
        &mut self,
        cx: &mut Context<'_>,
        dst: &TcpStream,
    ) -> Poll<io::Result<usize>> {
        debug_assert_ne!(self.buffered, 0);
        #[cfg(test)]
        if self.reject_write {
            return Poll::Ready(Err(io::Error::from_raw_os_error(libc::EINVAL)));
        }
        loop {
            ready!(dst.poll_write_ready(cx))?;
            match dst.try_io(Interest::WRITABLE, || {
                transfer(self.read.as_raw_fd(), dst.as_raw_fd(), self.buffered)
            }) {
                Ok(n) => {
                    self.buffered -= n;
                    #[cfg(test)]
                    SPLICED_BYTES.with(|bytes| bytes.set(bytes.get() + n as u64));
                    return Poll::Ready(Ok(n));
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                Err(e) => return Poll::Ready(Err(e)),
            }
        }
    }

    /// Recover already-consumed socket bytes when splice is unsupported.
    /// No readiness registration is needed: this pipe has one reader, and
    /// `buffered` counts bytes successfully spliced in but not yet removed.
    pub(super) fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            // SAFETY: buf is writable for the requested length; read owns the fd.
            let n = unsafe {
                libc::read(
                    self.read.as_raw_fd(),
                    buf.as_mut_ptr().cast(),
                    buf.len().min(self.buffered),
                )
            };
            if n >= 0 {
                self.buffered -= n as usize;
                return Ok(n as usize);
            }
            let e = io::Error::last_os_error();
            if e.kind() != io::ErrorKind::Interrupted {
                return Err(e);
            }
        }
    }
}

impl Drop for Pipe {
    fn drop(&mut self) {
        if self.enlarged {
            ENLARGED_PIPES.fetch_sub(1, Ordering::Relaxed);
        }
    }
}

fn transfer(src: RawFd, dst: RawFd, limit: usize) -> io::Result<usize> {
    loop {
        // SAFETY: both descriptors remain borrowed from live sockets/OwnedFds;
        // null offsets are required for sockets and pipes. Nothing blocks.
        let n = unsafe {
            libc::splice(
                src,
                std::ptr::null_mut(),
                dst,
                std::ptr::null_mut(),
                limit,
                libc::SPLICE_F_MOVE | libc::SPLICE_F_NONBLOCK,
            )
        };
        if n >= 0 {
            return Ok(n as usize);
        }
        let e = io::Error::last_os_error();
        if e.kind() != io::ErrorKind::Interrupted {
            return Err(e);
        }
    }
}

pub(super) fn unsupported(e: &io::Error) -> bool {
    matches!(
        e.raw_os_error(),
        Some(libc::EINVAL | libc::ENOSYS | libc::EOPNOTSUPP)
    )
}
