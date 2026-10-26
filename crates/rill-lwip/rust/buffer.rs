//! Bounded recycling across the core/consumer task boundary. Buffers return on
//! drop, including channel saturation, stream errors and aborted device writes.
use std::ops::{Deref, DerefMut};
use std::sync::{Arc, Mutex};

#[derive(Clone, Debug)]
pub(crate) struct BufferPool {
    inner: Arc<Mutex<FreeList>>,
    slots: usize,
    bytes: usize,
    capacity: usize,
}

#[derive(Debug, Default)]
struct FreeList {
    buffers: Vec<Vec<u8>>,
    bytes: usize,
}

impl BufferPool {
    pub(crate) fn new(slots: usize, bytes: usize, capacity: usize) -> Self {
        Self {
            inner: Arc::new(Mutex::new(FreeList::default())),
            slots,
            bytes,
            capacity,
        }
    }

    pub(crate) fn take(&self, size: usize) -> Buffer {
        if size == 0 {
            return Buffer {
                data: Vec::new(),
                pool: self.clone(),
            };
        }
        let mut data = {
            let mut free = self.inner.lock().unwrap();
            let data = free.buffers.pop().unwrap_or_default();
            free.bytes -= data.capacity();
            data
        };
        data.reserve(size.max(self.capacity));
        Buffer {
            data,
            pool: self.clone(),
        }
    }
}

#[derive(Debug)]
pub(crate) struct Buffer {
    data: Vec<u8>,
    pool: BufferPool,
}

impl Deref for Buffer {
    type Target = Vec<u8>;

    fn deref(&self) -> &Self::Target {
        &self.data
    }
}

impl DerefMut for Buffer {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.data
    }
}

impl BufferPool {
    /// Keep `data` for reuse if the cache has room; otherwise free it.
    fn recycle(&self, data: &mut Vec<u8>) {
        if data.capacity() == 0 {
            return;
        }
        let mut free = self.inner.lock().unwrap();
        if free.buffers.len() < self.slots && data.capacity() <= self.bytes - free.bytes {
            data.clear();
            free.bytes += data.capacity();
            free.buffers.push(std::mem::take(data));
        }
    }
}

impl Drop for Buffer {
    fn drop(&mut self) {
        self.pool.recycle(&mut self.data);
    }
}

/// Recycled storage for frames fed into [`crate::NetStack`]'s `Sink`, whose
/// item stays a plain `Vec<u8>`: the device pump takes a buffer here, the
/// core hands it back once the frame is copied into a pbuf. Steady-state
/// ingress then makes no malloc/free per packet — which on glibc also kept
/// the TUN pumps, migrating across worker threads, from growing an arena per
/// thread (+11 MB peak RSS on the 32-flow TUN leg).
#[derive(Clone, Debug)]
pub struct IngressBuffers(pub(crate) BufferPool);

impl IngressBuffers {
    /// An empty buffer with room for at least `len` bytes.
    pub fn take(&self, len: usize) -> Vec<u8> {
        let mut buffer = self.0.take(len);
        std::mem::take(&mut buffer.data)
    }

    pub(crate) fn give(&self, mut data: Vec<u8>) {
        self.0.recycle(&mut data);
    }
}

/// Reserved prefix for device framing (including Linux's virtio-net header).
pub const PACKET_HEADROOM: usize = 16;

/// An egress IP packet whose storage returns to a bounded pool on drop.
/// Dereferencing or `as_ref()` yields only the IP packet, without headroom.
#[derive(Debug)]
pub struct Packet(pub(crate) Buffer);

impl Packet {
    /// Full storage including [`PACKET_HEADROOM`] prefix bytes. Device writers
    /// may modify/expand it for offload; ordinary consumers should use `as_ref`.
    pub fn buffer_mut(&mut self) -> &mut Vec<u8> {
        &mut self.0
    }

    /// Capacity of the backing storage, including headroom.
    pub fn capacity(&self) -> usize {
        self.0.capacity()
    }

    /// Full storage including the reserved prefix, for a framed device write.
    pub fn buffer(&self) -> &[u8] {
        &self.0
    }
}

impl Deref for Packet {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0[PACKET_HEADROOM..]
    }
}

impl AsRef<[u8]> for Packet {
    fn as_ref(&self) -> &[u8] {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn storage_returns_on_drop_and_is_cleared() {
        let pool = BufferPool::new(2, 128, 32);
        let mut first = pool.take(16);
        first.extend_from_slice(b"packet");
        let ptr = first.as_ptr();
        drop(first);
        let second = pool.take(16);
        assert_eq!(second.as_ptr(), ptr);
        assert!(second.is_empty());
    }

    #[test]
    fn recycling_is_bounded_by_slots_and_bytes() {
        let pool = BufferPool::new(2, 64, 32);
        let buffers: Vec<_> = (0..4).map(|_| pool.take(32)).collect();
        drop(buffers);
        let free = pool.inner.lock().unwrap();
        assert_eq!(free.buffers.len(), 2);
        assert_eq!(free.bytes, 64);
        drop(free);
        drop(pool.take(128));
        assert!(pool.inner.lock().unwrap().bytes <= 64);
    }

    #[test]
    fn packet_hides_headroom_and_recycles_expanded_storage() {
        let pool = BufferPool::new(1, 65536, 64);
        let mut packet = Packet(pool.take(64));
        packet.buffer_mut().resize(PACKET_HEADROOM, 0);
        packet.buffer_mut().extend_from_slice(b"ip");
        assert_eq!(packet.as_ref(), b"ip");
        packet.buffer_mut().reserve(16000);
        let ptr = packet.buffer().as_ptr();
        drop(packet);
        assert_eq!(pool.take(64).as_ptr(), ptr);
    }

    #[test]
    fn full_and_closed_channels_return_packet_storage() {
        let pool = BufferPool::new(4, 4096, 64);
        let (tx, rx) = tokio::sync::mpsc::channel(1);
        let first = Packet(pool.take(64));
        tx.try_send(first).unwrap();
        let second = Packet(pool.take(64));
        let ptr = second.buffer().as_ptr();
        drop(tx.try_send(second).unwrap_err());
        assert_eq!(pool.take(64).as_ptr(), ptr);
        drop(rx);
        let third = Packet(pool.take(64));
        let ptr = third.buffer().as_ptr();
        drop(tx.try_send(third).unwrap_err());
        assert_eq!(pool.take(64).as_ptr(), ptr);
    }
}
