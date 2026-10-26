#![doc = include_str!("../README.md")]

mod buffer;
mod core;
mod heap;
mod lwip;
mod stack;
mod tcp_listener;
mod tcp_stream;
mod udp;
mod util;

pub use buffer::{IngressBuffers, Packet, PACKET_HEADROOM};
pub use stack::NetStack;
pub use tcp_listener::TcpListener;
pub use tcp_stream::TcpStream;
pub use {udp::RecvHalf as UdpRecvHalf, udp::SendHalf as UdpSendHalf, udp::UdpPkt, udp::UdpSocket};

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("LwIP error ({0})")]
    LwIP(i8),
}

pub type Result<T, E = Error> = std::result::Result<T, E>;
