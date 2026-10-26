//! Packet pumps between a [`tun_rs::AsyncDevice`] and the lwIP netstack.
//!
//! [`lwip::NetStack`] consumes raw IP packets and yields recycled egress frames,
//! while `tun-rs` exposes a packet-oriented `recv`/`send` pair. Two tasks
//! shuttle packets in each direction; either task exiting means the device
//! or the stack is gone, which `run()` treats as fatal for the listener.

use std::io;
use std::sync::Arc;

use futures::stream::{SplitSink, SplitStream};
#[cfg(target_os = "linux")]
use futures::FutureExt;
use futures::{SinkExt, StreamExt};
#[cfg(target_os = "linux")]
use lwip::Packet;
#[cfg(target_os = "linux")]
use lwip::PACKET_HEADROOM;
use lwip::{IngressBuffers, NetStack};
use tokio::task::JoinHandle;

use super::TunDevice;

/// One IP packet. UDP/TCP over IPv4/v6 tops out below 64 KiB regardless of
/// the device MTU, and a fixed buffer sidesteps MTU-change races.
const PACKET_BUF: usize = 65535;

/// Rebuild the same device without vnet headers if the kernel rejects offload.
/// Keep the factory around so addresses, MTU and txqueuelen apply to both paths.
pub(super) fn build_device(
    mut build: impl FnMut(bool) -> io::Result<tun_rs::AsyncDevice>,
) -> io::Result<tun_rs::AsyncDevice> {
    #[cfg(target_os = "linux")]
    {
        match build(true) {
            Ok(device) => {
                tracing::info!(
                    tcp_gso = device.tcp_gso(),
                    udp_gso = device.udp_gso(),
                    "TUN offload enabled"
                );
                return Ok(device);
            }
            Err(error) => {
                tracing::info!(%error, "TUN offload unavailable; falling back to per-packet I/O");
            }
        }
    }
    build(false)
}

/// What one pump task owns: its handle on the device and its half of the
/// netstack.
///
/// **Field order is load-bearing** (fields drop in declaration order): the
/// device handle must go before the stack half. Listener teardown aborts
/// the pumps and then waits for the lwIP core's `core_done`, which fires
/// once both stack halves are gone; a config reload builds the successor
/// listener right after. The last `Arc<TunDevice>` — whose drop deletes the
/// routes and closes the device — therefore has to be released *before*
/// the half that lets `core_done` fire. The other way round the old device
/// outlived `core_done` for as long as its route deletes took and the
/// successor's device create raced it: `EBUSY` on the configured name, a
/// 500 ms retry and a device renamed `rill-tun-1` (6 of 10 global-scope
/// restarts with four `/1` routes to delete, #375).
struct PumpEnd<D, H> {
    device: D,
    half: H,
}

pub(super) fn spawn_pumps(
    device: Arc<TunDevice>,
    stack: NetStack,
) -> (JoinHandle<io::Result<()>>, JoinHandle<io::Result<()>>) {
    let buffers = stack.ingress_buffers();
    let (stack_sink, stack_stream) = stack.split();
    let inbound = tokio::spawn(device_to_stack(
        PumpEnd {
            device: Arc::clone(&device),
            half: stack_sink,
        },
        buffers,
    ));
    let outbound = tokio::spawn(stack_to_device(PumpEnd {
        device,
        half: stack_stream,
    }));
    (inbound, outbound)
}

/// device → stack. Frames cross the netstack's `Sink<Vec<u8>>` in recycled
/// [`IngressBuffers`]; this path is not covered by the zero-alloc relay
/// invariant (ADR-0008), which starts at the terminated TCP stream.
///
/// `end` is only ever borrowed: moving its fields out into locals would
/// give them the locals' drop order (reverse of declaration) and undo
/// [`PumpEnd`]'s ordering.
async fn device_to_stack(
    mut end: PumpEnd<Arc<TunDevice>, SplitSink<NetStack, Vec<u8>>>,
    buffers: IngressBuffers,
) -> io::Result<()> {
    #[cfg(target_os = "linux")]
    if end.device.device.tcp_gso() {
        return device_to_stack_batched(&mut end, &buffers).await;
    }
    let mut buf = vec![0u8; PACKET_BUF];
    loop {
        let n = end.device.device.recv(&mut buf).await?;
        packet_from_device(&mut end, &buffers, &buf[..n]).await?;
    }
}

/// The single lwIP ingress point, shared by plain and GSO reads. The copy
/// lands in a recycled buffer the core hands back once the frame is in a
/// pbuf.
async fn packet_from_device(
    end: &mut PumpEnd<Arc<TunDevice>, SplitSink<NetStack, Vec<u8>>>,
    buffers: &IngressBuffers,
    packet: &[u8],
) -> io::Result<()> {
    if !packet.is_empty() {
        let mut frame = buffers.take(packet.len());
        frame.extend_from_slice(packet);
        end.half
            .send(frame)
            .await
            .map_err(|e| io::Error::other(format!("netstack ingress closed: {e}")))?;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
async fn device_to_stack_batched(
    end: &mut PumpEnd<Arc<TunDevice>, SplitSink<NetStack, Vec<u8>>>,
    buffers: &IngressBuffers,
) -> io::Result<()> {
    use tun_rs::{IDEAL_BATCH_SIZE, VIRTIO_NET_HDR_LEN};

    let mut original = vec![0; VIRTIO_NET_HDR_LEN + PACKET_BUF];
    let mtu = end.device.device.mtu()? as usize;
    let mut packets = vec![vec![0; mtu]; IDEAL_BATCH_SIZE];
    let mut sizes = vec![0; IDEAL_BATCH_SIZE];
    loop {
        let n = end
            .device
            .device
            .recv_multiple(&mut original, &mut packets, &mut sizes, 0)
            .await?;
        for (packet, &size) in packets[..n].iter().zip(&sizes[..n]) {
            packet_from_device(end, buffers, &packet[..size]).await?;
        }
    }
}

/// stack → device. Borrows `end` for the same reason as [`device_to_stack`].
async fn stack_to_device(
    mut end: PumpEnd<Arc<TunDevice>, SplitStream<NetStack>>,
) -> io::Result<()> {
    #[cfg(target_os = "linux")]
    if end.device.device.tcp_gso() {
        return stack_to_device_batched(&mut end).await;
    }
    while let Some(packet) = end.half.next().await {
        packet_to_device(&end.device, &packet?).await?;
    }
    Err(io::Error::other("netstack egress closed"))
}

async fn packet_to_device(device: &TunDevice, packet: &[u8]) -> io::Result<()> {
    let sent = device.device.send(packet).await?;
    if sent != packet.len() {
        return Err(io::Error::new(
            io::ErrorKind::WriteZero,
            "short TUN packet write",
        ));
    }
    Ok(())
}

/// tun-rs needs mutable, expandable storage including framing headroom. The
/// Packet still owns its pool return, even if GRO swaps or expands buffers.
#[cfg(target_os = "linux")]
struct OffloadPacket(Packet);

#[cfg(target_os = "linux")]
impl AsRef<[u8]> for OffloadPacket {
    fn as_ref(&self) -> &[u8] {
        self.0.buffer()
    }
}

#[cfg(target_os = "linux")]
impl AsMut<[u8]> for OffloadPacket {
    fn as_mut(&mut self) -> &mut [u8] {
        self.0.buffer_mut()
    }
}

#[cfg(target_os = "linux")]
impl tun_rs::ExpandBuffer for OffloadPacket {
    fn buf_capacity(&self) -> usize {
        self.0.capacity()
    }
    fn buf_resize(&mut self, len: usize, value: u8) {
        self.0.buffer_mut().resize(len, value);
    }
    fn buf_extend_from_slice(&mut self, bytes: &[u8]) {
        self.0.buffer_mut().extend_from_slice(bytes);
    }
}

/// Pull only packets already ready. A lone packet goes straight to the device;
/// the batch never waits for a second arrival or an aggregation timer.
#[cfg(target_os = "linux")]
fn drain_ready<S, T>(stream: &mut S, packets: &mut Vec<T>) -> io::Result<()>
where
    S: futures::Stream<Item = io::Result<T>> + Unpin,
{
    while packets.len() < tun_rs::IDEAL_BATCH_SIZE {
        match stream.next().now_or_never() {
            Some(Some(packet)) => packets.push(packet?),
            Some(None) | None => break,
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
async fn stack_to_device_batched(
    end: &mut PumpEnd<Arc<TunDevice>, SplitStream<NetStack>>,
) -> io::Result<()> {
    let mut gro = tun_rs::GROTable::default();
    let mut packets = Vec::with_capacity(tun_rs::IDEAL_BATCH_SIZE);
    let mut stream = (&mut end.half).map(|packet| packet.map(OffloadPacket));
    while let Some(packet) = stream.next().await {
        packets.push(packet?);
        drain_ready(&mut stream, &mut packets)?;
        packets_to_device(&end.device, &mut gro, &mut packets).await?;
        // Return storage only after send_multiple has finished with all frames.
        packets.clear();
    }
    Err(io::Error::other("netstack egress closed"))
}

#[cfg(target_os = "linux")]
async fn packets_to_device(
    device: &TunDevice,
    gro: &mut tun_rs::GROTable,
    packets: &mut [OffloadPacket],
) -> io::Result<()> {
    // GRO deliberately refuses to grow buffers. Give the leading packet room
    // to absorb a super-packet; its storage then circulates through the pool.
    if let Some(first) = packets.first_mut() {
        let buffer = first.0.buffer_mut();
        buffer.reserve(PACKET_BUF + 2 * PACKET_HEADROOM - buffer.len());
    }
    device
        .device
        .send_multiple(gro, packets, PACKET_HEADROOM)
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::PumpEnd;

    struct Recorder(&'static str, Arc<Mutex<Vec<&'static str>>>);

    impl Drop for Recorder {
        fn drop(&mut self) {
            self.1.lock().unwrap().push(self.0);
        }
    }

    /// The pump shape: an async fn that owns a `PumpEnd`, borrows its
    /// fields and is dropped (aborted) while suspended.
    async fn parked(mut end: PumpEnd<Recorder, Recorder>) {
        let _borrows = (&end.device, &mut end.half);
        std::future::pending::<()>().await;
    }

    /// Teardown ordering behind global-scope restarts (#375): an aborted
    /// pump must release the device before its stack half, so the device
    /// is closed by the time `core_done` lets a successor be built.
    #[tokio::test]
    async fn aborted_pump_releases_the_device_before_its_stack_half() {
        let order = Arc::new(Mutex::new(Vec::new()));
        let task = tokio::spawn(parked(PumpEnd {
            device: Recorder("device", Arc::clone(&order)),
            half: Recorder("stack half", Arc::clone(&order)),
        }));
        tokio::task::yield_now().await;
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        assert_eq!(*order.lock().unwrap(), ["device", "stack half"]);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn batch_drains_only_ready_packets_and_keeps_order() {
        use futures::{stream, StreamExt};
        let mut packets = vec![0];
        let mut ready = stream::iter((1..4).map(Ok)).chain(stream::pending());
        super::drain_ready(&mut ready, &mut packets).unwrap();
        assert_eq!(packets, [0, 1, 2, 3]);

        let mut lone = vec![42];
        super::drain_ready(&mut stream::pending(), &mut lone).unwrap();
        assert_eq!(lone, [42], "never wait for another packet");

        let mut many = stream::iter((0..1000).map(Ok));
        let mut limited = Vec::new();
        super::drain_ready(&mut many, &mut limited).unwrap();
        assert_eq!(limited.len(), tun_rs::IDEAL_BATCH_SIZE);
        assert_eq!(limited[limited.len() - 1], tun_rs::IDEAL_BATCH_SIZE - 1);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn offload_failure_retries_the_same_factory_without_offload() {
        let mut attempts = Vec::new();
        let result = super::build_device(|offload| {
            attempts.push(offload);
            Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "test device",
            ))
        });
        assert!(result.is_err());
        assert_eq!(attempts, [true, false]);
    }
}
