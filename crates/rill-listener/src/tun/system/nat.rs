//! Bounded port NAT. Accepted flows live with their handler; incomplete
//! handshakes expire, and closed tuples linger for kernel FIN/TIME_WAIT —
//! long only when the listener side closed first.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::Mutex;

const FIRST_PORT: u16 = 1024;
const HALF_OPEN: Duration = Duration::from_secs(30);
// Linux's TIME_WAIT is 60 seconds. A listener-side socket that closed
// first sits in it, and a new SYN reusing its NAT port could be refused, so
// its mapping is held that long.
const CLOSED: Duration = Duration::from_secs(60);
// Every other close — the client's FIN came first, so the listener socket
// closes passively without TIME_WAIT, or a RST ended the flow — only needs
// the mapping while FIN/ACK retransmissions cross the pump. Holding all of
// them 60 s capped the backend at 64 512 / 60 ≈ 1 075 new flows/s sustained:
// a 10 s conn-rate run stalled after ~63 k connections.
const CLOSED_PASSIVE: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(in crate::tun) struct Flow {
    pub src: SocketAddr,
    pub dst: SocketAddr,
}

struct Entry {
    flow: Flow,
    state: State,
    /// Who sent the first FIN, if anyone yet; a RST counts as the client's
    /// (neither side keeps TIME_WAIT after one).
    first_fin: Option<Side>,
}

/// The two TCP endpoints a NAT entry joins.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Side {
    /// The original client, seen on the device as the flow's source.
    Client,
    /// The kernel listener's accepted socket.
    Listener,
}

enum State {
    HalfOpen(Instant),
    Accepted,
    Closed(Instant),
}

pub(super) struct Nat {
    flows: HashMap<Flow, u16>,
    ports: HashMap<u16, Entry>,
    next: u16,
    last_port: u16,
    sweep_at: Instant,
}

impl Nat {
    pub fn new() -> Self {
        Self::with_last_port(u16::MAX)
    }

    fn with_last_port(last_port: u16) -> Self {
        Self {
            flows: HashMap::new(),
            ports: HashMap::new(),
            next: FIRST_PORT,
            last_port,
            sweep_at: Instant::now(),
        }
    }

    pub fn expire(&mut self, now: Instant) {
        if now < self.sweep_at {
            return;
        }
        self.sweep_at = now + Duration::from_secs(1);
        self.ports.retain(|port, entry| {
            let expired = match entry.state {
                State::HalfOpen(deadline) | State::Closed(deadline) => now >= deadline,
                State::Accepted => false,
            };
            if expired && self.flows.get(&entry.flow) == Some(port) {
                self.flows.remove(&entry.flow);
            }
            !expired
        });
    }

    pub fn port(&mut self, flow: Flow, syn: bool, now: Instant) -> Option<u16> {
        self.expire(now);
        if let Some(&port) = self.flows.get(&flow) {
            if !syn || !matches!(self.ports[&port].state, State::Closed(_)) {
                self.ports.get_mut(&port)?.refresh(now);
                return Some(port);
            }
            // A new SYN may reconnect before the old kernel TIME_WAIT
            // ends. Allocate a different port, retaining the old reverse
            // mapping for late packets from that kernel socket.
        }
        // A late ACK/RST must not create a fresh mapping into an unrelated
        // kernel socket. Only initial SYNs allocate entries.
        if !syn {
            return None;
        }
        if self.ports.len() > usize::from(self.last_port - FIRST_PORT) && !self.evict_closed() {
            return None;
        }
        for _ in FIRST_PORT..=self.last_port {
            let port = self.next;
            self.next = if port == self.last_port {
                FIRST_PORT
            } else {
                port + 1
            };
            if let std::collections::hash_map::Entry::Vacant(slot) = self.ports.entry(port) {
                slot.insert(Entry {
                    flow,
                    state: State::HalfOpen(now + HALF_OPEN),
                    first_fin: None,
                });
                self.flows.insert(flow, port);
                return Some(port);
            }
        }
        None
    }

    pub fn reverse(&mut self, port: u16, now: Instant) -> Option<Flow> {
        let entry = self.ports.get_mut(&port)?;
        entry.refresh(now);
        Some(entry.flow)
    }

    pub fn accept(table: &Arc<Mutex<Self>>, port: u16) -> Option<(Flow, Lease)> {
        let mut nat = table.lock();
        let entry = nat.ports.get_mut(&port)?;
        if !matches!(entry.state, State::HalfOpen(_)) {
            return None;
        }
        entry.state = State::Accepted;
        Some((
            entry.flow,
            Lease {
                table: Arc::clone(table),
                port,
            },
        ))
    }

    /// Record a FIN or RST crossing the pump from `side`.
    pub fn note_close(&mut self, port: u16, side: Side, fin: bool, rst: bool, now: Instant) {
        let Some(entry) = self.ports.get_mut(&port) else {
            return;
        };
        if rst {
            entry.first_fin = Some(Side::Client);
        } else if fin && entry.first_fin.is_none() {
            entry.first_fin = Some(side);
        }
        let linger = entry.linger();
        if let State::Closed(deadline) = &mut entry.state {
            *deadline = (*deadline).min(now + linger);
        }
    }

    fn close(&mut self, port: u16, now: Instant) {
        if let Some(entry) = self.ports.get_mut(&port) {
            // Keep both directions until FIN/ACKs have crossed the pump.
            entry.state = State::Closed(now + entry.linger());
        }
    }

    /// Out of ports: take back the passively closed mapping due to expire
    /// first rather than refusing the SYN. Mappings guarding a listener
    /// socket in TIME_WAIT are never taken — a SYN reusing that port could
    /// be refused by it.
    fn evict_closed(&mut self) -> bool {
        let Some(port) = self
            .ports
            .iter()
            .filter_map(|(&port, entry)| match entry.state {
                State::Closed(deadline) if entry.first_fin == Some(Side::Client) => {
                    Some((deadline, port))
                }
                _ => None,
            })
            .min()
            .map(|(_, port)| port)
        else {
            return false;
        };
        let entry = self.ports.remove(&port).expect("listed above");
        if self.flows.get(&entry.flow) == Some(&port) {
            self.flows.remove(&entry.flow);
        }
        true
    }
}

impl Entry {
    /// Traffic on a closed mapping restarts its linger.
    fn refresh(&mut self, now: Instant) {
        let linger = self.linger();
        if let State::Closed(deadline) = &mut self.state {
            *deadline = now + linger;
        }
    }

    fn linger(&self) -> Duration {
        match self.first_fin {
            // No FIN yet: the listener socket is about to close first.
            Some(Side::Listener) | None => CLOSED,
            Some(Side::Client) => CLOSED_PASSIVE,
        }
    }
}

pub(in crate::tun) struct Lease {
    table: Arc<Mutex<Nat>>,
    port: u16,
}

impl Drop for Lease {
    fn drop(&mut self) {
        self.table.lock().close(self.port, Instant::now());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn flow(port: u16) -> Flow {
        Flow {
            src: SocketAddr::from(([10, 0, 0, 1], port)),
            dst: "198.18.1.2:443".parse().unwrap(),
        }
    }

    #[test]
    fn collisions_exhaustion_and_half_open_expiry() {
        let now = Instant::now();
        let mut nat = Nat::with_last_port(1025);
        assert!(nat.port(flow(1), false, now).is_none());
        assert_eq!(nat.port(flow(1), true, now), Some(1024));
        assert_eq!(nat.port(flow(1), true, now), Some(1024));
        assert_eq!(nat.port(flow(2), true, now), Some(1025));
        assert!(nat.port(flow(3), true, now).is_none());
        nat.expire(now + HALF_OPEN);
        assert!(nat.reverse(1024, now).is_none());
        assert_eq!(nat.port(flow(3), true, now + HALF_OPEN), Some(1024));
    }

    #[test]
    fn accepted_flow_lifetime_and_fin_linger() {
        let now = Instant::now();
        let nat = Arc::new(Mutex::new(Nat::with_last_port(1024)));
        nat.lock().port(flow(1), true, now).unwrap();
        let (original, lease) = Nat::accept(&nat, 1024).unwrap();
        assert_eq!(original, flow(1));
        assert!(Nat::accept(&nat, 1024).is_none());
        nat.lock().expire(now + HALF_OPEN * 2);
        assert_eq!(nat.lock().reverse(1024, now), Some(flow(1)));
        drop(lease);
        assert_eq!(nat.lock().reverse(1024, now), Some(flow(1)));
        assert!(nat.lock().port(flow(2), true, now).is_none());
        assert!(nat.lock().port(flow(1), true, now).is_none());
        assert_eq!(nat.lock().port(flow(1), false, now), Some(1024));
        nat.lock().expire(now + CLOSED * 2);
        assert_eq!(nat.lock().port(flow(2), true, now + CLOSED * 2), Some(1024));
    }

    #[test]
    fn passive_close_lingers_briefly_and_is_evictable() {
        let now = Instant::now();
        let nat = Arc::new(Mutex::new(Nat::with_last_port(1025)));
        // Flow 1: the client's FIN comes first — no TIME_WAIT behind it.
        nat.lock().port(flow(1), true, now).unwrap();
        let (_, lease) = Nat::accept(&nat, 1024).unwrap();
        nat.lock().note_close(1024, Side::Client, true, false, now);
        nat.lock()
            .note_close(1024, Side::Listener, true, false, now);
        drop(lease);
        // Flow 2: the listener closes first and sits in TIME_WAIT.
        nat.lock().port(flow(2), true, now).unwrap();
        let (_, lease) = Nat::accept(&nat, 1025).unwrap();
        nat.lock()
            .note_close(1025, Side::Listener, true, false, now);
        drop(lease);

        // Out of ports: only the passive mapping is given up.
        assert_eq!(nat.lock().port(flow(3), true, now), Some(1024));
        assert!(nat.lock().port(flow(4), true, now).is_none());
        assert_eq!(nat.lock().reverse(1025, now), Some(flow(2)));

        // Unevicted, a passive close expires after CLOSED_PASSIVE and an
        // active one after CLOSED.
        let nat = Arc::new(Mutex::new(Nat::with_last_port(1025)));
        nat.lock().port(flow(1), true, now).unwrap();
        let (_, passive) = Nat::accept(&nat, 1024).unwrap();
        nat.lock().note_close(1024, Side::Client, false, true, now);
        drop(passive);
        nat.lock().port(flow(2), true, now).unwrap();
        let (_, active) = Nat::accept(&nat, 1025).unwrap();
        drop(active);
        let later = now + CLOSED_PASSIVE + Duration::from_secs(1);
        nat.lock().expire(later);
        assert!(
            nat.lock().reverse(1024, later).is_none(),
            "RST: brief linger"
        );
        assert_eq!(nat.lock().reverse(1025, later), Some(flow(2)));
    }

    #[test]
    fn reconnect_does_not_reuse_time_wait_port_or_lose_new_index() {
        let now = Instant::now();
        let nat = Arc::new(Mutex::new(Nat::with_last_port(1025)));
        nat.lock().port(flow(1), true, now).unwrap();
        let (_, lease) = Nat::accept(&nat, 1024).unwrap();
        drop(lease);
        // The final client ACK still needs the old forward mapping.
        assert_eq!(nat.lock().port(flow(1), false, now), Some(1024));
        assert_eq!(nat.lock().port(flow(1), true, now), Some(1025));
        let (_, current) = Nat::accept(&nat, 1025).unwrap();
        nat.lock().expire(now + CLOSED * 2);
        assert_eq!(nat.lock().reverse(1024, now), None);
        assert_eq!(
            nat.lock().port(flow(1), false, now + CLOSED * 2),
            Some(1025)
        );
        drop(current);
    }
}
