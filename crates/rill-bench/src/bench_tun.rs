//! TUN inbound workload (`--only tun`, Linux only).
//!
//! Runs the W1–W3 TCP legs through each proxy's TUN device instead of its
//! SOCKS5 listener, so every byte crosses the proxy's userspace TCP/IP
//! stack — rill's lwIP core, mihomo's `stack: system` / `stack: gvisor` —
//! which the SOCKS5 legs never touch.
//!
//! Topology, all inside one fresh network namespace:
//!
//! ```text
//! client ── connect(198.18.x.y:port) ──▶ route 198.18.0.0/16 dev rillbench0
//!   ──▶ proxy TUN stack ── fake IP → echo.bench ──▶ MATCH,DIRECT
//!   ── echo.bench via the harness's upstream DNS (→ 127.0.0.1) ──▶ echo server
//! ```
//!
//! Both proxies run `auto-route: false`; the harness installs the single
//! fake-ip route itself so the routed set is identical. The outbound is a
//! loopback DIRECT dial, which never falls in the fake range, so no loop
//! avoidance (interface binding, fwmark) is involved.
//!
//! The namespace requirement is a safety rail, not a convenience: the
//! workload creates a TUN device and installs a route, and on a host that
//! already runs a TUN proxy (whose fake-ip range is usually this same
//! 198.18.0.0/16) doing that in the host namespace would hijack live
//! traffic. Run it as `sudo unshare --net -- rill-bench --only tun …`
//! (`bench-tun.sh` does); the namespace and everything in it vanish when
//! the harness exits.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{Name, RData, Record, RecordType};
use hickory_proto::serialize::binary::BinEncodable;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::task::JoinHandle;

use crate::bench_connrate::{self, ConnRateResult};
use crate::bench_latency::{self, LatencyResult};
use crate::bench_memory;
use crate::bench_throughput::{self, ThroughputResult};
use crate::dial::Dial;
use crate::echo_server;
use crate::results::BenchMeta;
use crate::{Args, ChildGuard};

/// TUN device both proxies create. Fixed so a stale one left by a crashed
/// run is detectable before the next spawn.
const DEVICE: &str = "rillbench0";
/// Address assigned to the device — inside the private namespace, so it
/// cannot collide with a host bridge.
const TUN_ADDR: &str = "172.19.0.1/30";
/// Fake-ip pool both configs allocate from, and the one route the harness
/// points into the device.
const FAKE_IP_RANGE: &str = "198.18.0.1/16";
const FAKE_IP_ROUTE: &str = "198.18.0.0/16";
/// The proxies' DNS listener — the harness resolves `ECHO_DOMAIN` here to
/// learn the fake IP it dials.
const PROXY_DNS_PORT: u16 = 15360;
/// `.bench` avoids every entry in mihomo's default fake-ip-filter (which
/// covers `*.test`), so both proxies answer it with a fake IP.
const ECHO_DOMAIN: &str = "echo.bench.";
/// Extra fake IPs (`echo-0.bench.` …) the conn-rate leg spreads over, so
/// client-side TIME_WAIT toward one fake IP cannot cap it — see
/// [`bench_connrate::bench_conn_rate_across`].
const CONNRATE_TARGETS: usize = 16;
/// Pause between targets so the previous device is gone and its
/// TIME_WAIT sockets don't share a 4-tuple space with the next run.
const TARGET_COOLDOWN: Duration = Duration::from_secs(15);
/// The parallel leg: `PARALLEL_FLOWS` concurrent echo transfers of
/// `PARALLEL_SIZE` each (1 GiB relayed in total).
const PARALLEL_FLOWS: usize = 32;
const PARALLEL_SIZE: usize = 16 * 1024 * 1024;

/// One proxy configuration under test.
enum Flavor {
    Rill,
    Mihomo { stack: String },
}

struct TunTarget {
    name: String,
    binary: PathBuf,
    flavor: Flavor,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct TunTargetResult {
    pub target: String,
    pub rss_idle_bytes: u64,
    pub rss_load_bytes: u64,
    pub throughput: Vec<ThroughputResult>,
    /// Proxy CPU time (user + sys, all threads) spent across the whole
    /// throughput leg, divided by the GB it relayed (both directions).
    pub throughput_cpu_secs_per_gb: f64,
    /// `PARALLEL_FLOWS` concurrent transfers — what a single flow never
    /// shows: flows competing for the stack and its shared buffers.
    pub parallel: ThroughputResult,
    pub parallel_cpu_secs_per_gb: f64,
    pub latency: LatencyResult,
    pub conn_rate: ConnRateResult,
    /// Proxy CPU time per connection across the conn-rate leg.
    pub connrate_cpu_us_per_conn: f64,
    /// Packets the kernel dropped handing them to the proxy (the device's
    /// `tx_dropped`) over the whole run: the proxy read too slowly and the
    /// TUN queue overflowed. Non-zero means some legs paid for loss
    /// recovery.
    pub tun_tx_dropped: u64,
}

#[derive(Debug, serde::Serialize)]
pub struct TunReport {
    pub meta: BenchMeta,
    pub mtu: u16,
    pub targets: Vec<TunTargetResult>,
}

pub async fn run_tun_test(args: &Args) -> anyhow::Result<()> {
    // SAFETY: geteuid has no preconditions.
    anyhow::ensure!(
        unsafe { libc::geteuid() } == 0,
        "the tun workload creates a TUN device and a route — run it as root \
         inside a fresh network namespace: sudo unshare --net -- rill-bench --only tun …"
    );
    ensure_private_netns()?;
    run_ip(&["link", "set", "lo", "up"])?;

    let mut targets = vec![TunTarget {
        name: "rill (lwip)".to_string(),
        binary: args.rust_binary.clone(),
        flavor: Flavor::Rill,
    }];
    if let Some(go) = &args.go_binary {
        for stack in &args.tun_mihomo_stacks {
            targets.push(TunTarget {
                name: format!("mihomo ({stack})"),
                binary: go.clone(),
                flavor: Flavor::Mihomo {
                    stack: stack.clone(),
                },
            });
        }
    } else {
        eprintln!("[tun] no --go-binary: running the rill leg only");
    }

    let (upstream, upstream_handle) = start_upstream_dns().await?;
    eprintln!("[tun] upstream DNS on {upstream} (any A → 127.0.0.1)");

    let mut results = Vec::with_capacity(targets.len());
    for (i, target) in targets.iter().enumerate() {
        if i > 0 {
            eprintln!("[tun] cooling down {}s...", TARGET_COOLDOWN.as_secs());
            tokio::time::sleep(TARGET_COOLDOWN).await;
        }
        results.push(bench_tun_target(target, args, upstream).await?);
    }
    upstream_handle.abort();

    let report = TunReport {
        meta: crate::collect_meta(args),
        mtu: args.tun_mtu,
        targets: results,
    };
    let json = serde_json::to_string_pretty(&report)?;
    if let Some(output_path) = &args.output {
        std::fs::write(output_path, &json)?;
        eprintln!("results written to {}", output_path.display());
    } else {
        println!("{json}");
    }
    if args.markdown {
        eprintln!("\n--- Markdown ---\n");
        println!("{}", render_markdown(&report)?);
    }
    Ok(())
}

async fn bench_tun_target(
    target: &TunTarget,
    args: &Args,
    upstream: SocketAddr,
) -> anyhow::Result<TunTargetResult> {
    let name = target.name.as_str();
    anyhow::ensure!(
        !device_exists(DEVICE)?,
        "{name}: TUN device {DEVICE} already exists — a stale proxy is still running"
    );
    let dns_addr: SocketAddr = (Ipv4Addr::LOCALHOST, PROXY_DNS_PORT).into();
    crate::ensure_udp_port_free(dns_addr, name)?;

    // A private home keeps mihomo's cache/geodata files (and rill's
    // controller file) out of root's real config directory.
    let home = tempfile::tempdir()?;
    let config_path = home.path().join("config.yaml");
    std::fs::write(
        &config_path,
        config_yaml(&target.flavor, args.tun_mtu, upstream),
    )?;

    let (echo_addr, echo_handle) = echo_server::start_echo_server().await?;
    eprintln!("[{name}] echo server on {echo_addr}");
    eprintln!("[{name}] starting proxy: {}", target.binary.display());
    let mut child = ChildGuard::new(spawn_with_home(&target.binary, home.path(), &config_path)?);
    let pid = child.id();

    wait_for_device_up(&mut child, name, Duration::from_secs(15)).await?;
    crate::wait_for_udp_port_guarded(dns_addr, Duration::from_secs(10), &mut child, name).await?;
    let route = FakeIpRoute::install()?;
    let fake_ip = resolve_fake_ip(dns_addr, ECHO_DOMAIN).await?;
    let echo = SocketAddr::new(IpAddr::V4(fake_ip), echo_addr.port());
    ensure_routed_into_device(fake_ip)?;
    eprintln!("[{name}] {ECHO_DOMAIN} → {fake_ip}, routed into {DEVICE}");
    let mut connrate_targets = Vec::with_capacity(CONNRATE_TARGETS);
    for i in 0..CONNRATE_TARGETS {
        let ip = resolve_fake_ip(dns_addr, &format!("echo-{i}.bench.")).await?;
        connrate_targets.push(SocketAddr::new(IpAddr::V4(ip), echo_addr.port()));
    }

    // One strict probe first: a datapath that cannot echo must fail the
    // target loudly, not score a few timed-out warmups as a result.
    tokio::time::timeout(Duration::from_secs(10), echo_once(echo))
        .await
        .map_err(|_| anyhow::anyhow!("{name}: first TUN echo through {echo} timed out"))?
        .map_err(|e| anyhow::anyhow!("{name}: first TUN echo through {echo} failed: {e}"))?;

    tokio::time::sleep(Duration::from_secs(2)).await;
    let drops_at_start = device_tx_dropped()?;
    let rss_idle = bench_memory::measure_rss(pid)?;
    eprintln!("[{name}] idle RSS: {:.1} MB", rss_idle as f64 / 1_048_576.0);

    eprintln!("[{name}] warming up...");
    for _ in 0..50 {
        let _ = tokio::time::timeout(Duration::from_secs(10), echo_once(echo)).await;
    }

    eprintln!("[{name}] benchmarking throughput...");
    let cpu_before = cpu_seconds(pid)?;
    let throughput = bench_throughput::bench_throughput(Dial::Direct, echo).await?;
    let cpu_throughput = cpu_seconds(pid)? - cpu_before;
    let relayed_gb = throughput.iter().map(|t| t.total_bytes).sum::<u64>() as f64 / 1e9;
    let throughput_cpu_secs_per_gb = cpu_throughput / relayed_gb;
    eprintln!("  proxy CPU: {throughput_cpu_secs_per_gb:.3} s per GB relayed");

    let drops_before_parallel = device_tx_dropped()?;
    let cpu_before = cpu_seconds(pid)?;
    let parallel =
        bench_throughput::bench_parallel(Dial::Direct, echo, PARALLEL_SIZE, PARALLEL_FLOWS).await?;
    let parallel_cpu_secs_per_gb =
        (cpu_seconds(pid)? - cpu_before) / (parallel.total_bytes as f64 / 1e9);
    eprintln!("  proxy CPU: {parallel_cpu_secs_per_gb:.3} s per GB relayed (parallel)");
    eprintln!(
        "  TUN tx_dropped during parallel: {}",
        device_tx_dropped()? - drops_before_parallel
    );

    eprintln!("[{name}] benchmarking latency...");
    let latency = bench_latency::bench_latency(Dial::Direct, echo, args.latency_iterations).await?;

    eprintln!("[{name}] benchmarking connection rate...");
    let rss_handle = tokio::spawn({
        let duration = args.duration;
        async move { bench_memory::measure_peak_rss(pid, duration).await }
    });
    let cpu_before = cpu_seconds(pid)?;
    let conn_rate = bench_connrate::bench_conn_rate_across(
        Dial::Direct,
        &connrate_targets,
        args.duration,
        args.concurrency,
    )
    .await?;
    let cpu_connrate = cpu_seconds(pid)? - cpu_before;
    let rss_load = rss_handle.await??;
    let connrate_cpu_us_per_conn = if conn_rate.total_connections == 0 {
        0.0
    } else {
        cpu_connrate * 1e6 / conn_rate.total_connections as f64
    };
    eprintln!("  proxy CPU: {connrate_cpu_us_per_conn:.0} µs per connection");
    eprintln!("[{name}] load RSS: {:.1} MB", rss_load as f64 / 1_048_576.0);
    let tun_tx_dropped = device_tx_dropped()? - drops_at_start;
    eprintln!("[{name}] TUN tx_dropped over the run: {tun_tx_dropped}");

    drop(route);
    child.shutdown().await;
    echo_handle.abort();
    wait_for_device_gone(Duration::from_secs(10)).await?;

    Ok(TunTargetResult {
        target: name.to_string(),
        rss_idle_bytes: rss_idle,
        rss_load_bytes: rss_load,
        throughput,
        throughput_cpu_secs_per_gb,
        parallel,
        parallel_cpu_secs_per_gb,
        latency,
        conn_rate,
        connrate_cpu_us_per_conn,
        tun_tx_dropped,
    })
}

/// The YAML both binaries share except for the `tun:` block: rill takes
/// `inet4-address` as a string and ignores `stack`; mihomo wants a list
/// and needs interface auto-detection off (no physical interface here).
fn config_yaml(flavor: &Flavor, mtu: u16, upstream: SocketAddr) -> String {
    let tun = match flavor {
        Flavor::Rill => format!(
            "tun:\n  enable: true\n  device: {DEVICE}\n  mtu: {mtu}\n  \
             inet4-address: {TUN_ADDR}\n  auto-route: false\n"
        ),
        Flavor::Mihomo { stack } => format!(
            "tun:\n  enable: true\n  stack: {stack}\n  device: {DEVICE}\n  mtu: {mtu}\n  \
             inet4-address:\n    - {TUN_ADDR}\n  auto-route: false\n  \
             auto-detect-interface: false\n"
        ),
    };
    format!(
        "mode: rule\n\
         log-level: warning\n\
         ipv6: false\n\
         # Conn-rate legs exceed rill's default 256-conn cap; mihomo ignores it.\n\
         max-connections: 0\n\
         dns:\n  \
           enable: true\n  \
           listen: 127.0.0.1:{PROXY_DNS_PORT}\n  \
           enhanced-mode: fake-ip\n  \
           fake-ip-range: {FAKE_IP_RANGE}\n  \
           nameserver:\n    - udp://{upstream}\n\
         {tun}\
         rules:\n  - MATCH,DIRECT\n"
    )
}

fn spawn_with_home(
    binary: &Path,
    home: &Path,
    config: &Path,
) -> anyhow::Result<std::process::Child> {
    Command::new(binary)
        .arg("-d")
        .arg(home)
        .arg("-f")
        .arg(config)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|e| anyhow::anyhow!("failed to start {}: {e}", binary.display()))
}

/// Answers every A query with 127.0.0.1 — the proxies' DIRECT dial
/// resolves `echo.bench` here, landing on the loopback echo server.
async fn start_upstream_dns() -> anyhow::Result<(SocketAddr, JoinHandle<()>)> {
    let sock = UdpSocket::bind("127.0.0.1:0").await?;
    let addr = sock.local_addr()?;
    let handle = tokio::spawn(async move {
        let mut buf = [0u8; 512];
        loop {
            let Ok((n, peer)) = sock.recv_from(&mut buf).await else {
                continue;
            };
            let Ok(query) = Message::from_vec(&buf[..n]) else {
                continue;
            };
            let mut reply = Message::new(query.id, MessageType::Response, query.op_code);
            reply.metadata.recursion_desired = query.recursion_desired;
            reply.metadata.recursion_available = true;
            for q in &query.queries {
                reply.add_query(q.clone());
                if q.query_type() == RecordType::A {
                    reply.add_answer(Record::from_rdata(
                        q.name().clone(),
                        60,
                        RData::A(A(Ipv4Addr::LOCALHOST)),
                    ));
                }
            }
            if let Ok(bytes) = reply.to_bytes() {
                let _ = sock.send_to(&bytes, peer).await;
            }
        }
    });
    Ok((addr, handle))
}

/// Ask the proxy's DNS for `domain` and insist on a fake IP — a real
/// answer would send the workload straight to loopback, bypassing the TUN
/// stack while still producing plausible numbers.
async fn resolve_fake_ip(dns: SocketAddr, domain: &str) -> anyhow::Result<Ipv4Addr> {
    let sock = UdpSocket::bind("127.0.0.1:0").await?;
    let mut msg = Message::new(0x7475, MessageType::Query, OpCode::Query);
    msg.metadata.recursion_desired = true;
    let name: Name = domain.parse()?;
    msg.add_query(Query::query(name, RecordType::A));
    sock.send_to(&msg.to_bytes()?, dns).await?;

    let mut buf = [0u8; 512];
    let (n, _) = tokio::time::timeout(Duration::from_secs(2), sock.recv_from(&mut buf))
        .await
        .map_err(|_| anyhow::anyhow!("no DNS answer for {domain} from {dns}"))??;
    let reply = Message::from_vec(&buf[..n])?;
    let ip = reply
        .answers
        .iter()
        .find_map(|r| match r.data {
            RData::A(A(ip)) => Some(ip),
            _ => None,
        })
        .ok_or_else(|| anyhow::anyhow!("DNS answer for {domain} carried no A record"))?;
    anyhow::ensure!(
        ip.octets()[..2] == [198, 18],
        "{domain} resolved to {ip}, not a fake IP in {FAKE_IP_ROUTE} — the proxy is \
         not in fake-ip mode, so the workload would bypass the TUN stack"
    );
    Ok(ip)
}

async fn echo_once(target: SocketAddr) -> std::io::Result<()> {
    let mut stream = Dial::Direct.connect(target).await?;
    stream.write_all(&[0x42]).await?;
    let mut buf = [0u8; 1];
    stream.read_exact(&mut buf).await?;
    Ok(())
}

/// The fake-ip route, removed on drop. The device's exit takes its routes
/// with it anyway; the explicit delete covers a proxy that outlives the
/// guard.
struct FakeIpRoute;

impl FakeIpRoute {
    fn install() -> anyhow::Result<Self> {
        run_ip(&["route", "replace", FAKE_IP_ROUTE, "dev", DEVICE])?;
        Ok(Self)
    }
}

impl Drop for FakeIpRoute {
    fn drop(&mut self) {
        let _ = Command::new("ip")
            .args(["route", "del", FAKE_IP_ROUTE, "dev", DEVICE])
            .stderr(Stdio::null())
            .status();
    }
}

fn run_ip(args: &[&str]) -> anyhow::Result<String> {
    let out = Command::new("ip")
        .args(args)
        .output()
        .map_err(|e| anyhow::anyhow!("failed to run `ip`: {e}"))?;
    anyhow::ensure!(
        out.status.success(),
        "`ip {}` failed: {}",
        args.join(" "),
        String::from_utf8_lossy(&out.stderr).trim()
    );
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Interface names in the *current* network namespace. `/proc/net/dev`
/// follows the reader's namespace; `/sys/class/net` follows the namespace
/// sysfs was mounted in, which after a bare `unshare --net` is still the
/// host's.
fn netns_interfaces() -> anyhow::Result<Vec<String>> {
    let dev = std::fs::read_to_string("/proc/net/dev")?;
    Ok(dev
        .lines()
        .skip(2)
        .filter_map(|l| l.split_once(':').map(|(name, _)| name.trim().to_string()))
        .collect())
}

fn ensure_private_netns() -> anyhow::Result<()> {
    let ifaces = netns_interfaces()?;
    anyhow::ensure!(
        ifaces.iter().all(|i| i == "lo"),
        "the tun workload must run in a fresh network namespace (found interfaces: {}) — \
         installing its fake-ip route here could hijack a live TUN proxy's traffic. \
         Run: sudo unshare --net -- rill-bench --only tun …",
        ifaces.join(", ")
    );
    Ok(())
}

/// The TUN device's `tx_dropped` from `/proc/net/dev`: packets the kernel
/// routed into the device but dropped because the proxy's read side was
/// behind (the queue toward userspace is ~500 packets).
fn device_tx_dropped() -> anyhow::Result<u64> {
    let dev = std::fs::read_to_string("/proc/net/dev")?;
    let fields = dev
        .lines()
        .filter_map(|l| l.split_once(':'))
        .find(|(name, _)| name.trim() == DEVICE)
        .map(|(_, rest)| rest.split_whitespace().collect::<Vec<_>>())
        .ok_or_else(|| anyhow::anyhow!("{DEVICE} missing from /proc/net/dev"))?;
    // 8 receive columns, then transmit: bytes packets errs drop …
    fields
        .get(11)
        .ok_or_else(|| anyhow::anyhow!("/proc/net/dev: short line for {DEVICE}"))?
        .parse()
        .map_err(|e| anyhow::anyhow!("/proc/net/dev tx_drop for {DEVICE}: {e}"))
}

fn device_exists(name: &str) -> anyhow::Result<bool> {
    Ok(netns_interfaces()?.iter().any(|i| i == name))
}

async fn wait_for_device_up(
    child: &mut ChildGuard,
    what: &str,
    timeout: Duration,
) -> anyhow::Result<()> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        child.ensure_alive(what)?;
        if device_exists(DEVICE)? && link_is_up(&run_ip(&["-o", "link", "show", "dev", DEVICE])?) {
            return Ok(());
        }
        if tokio::time::Instant::now() >= deadline {
            anyhow::bail!("{what}: TUN device {DEVICE} not up after {timeout:?}");
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// Whether an `ip -o link` line carries the administrative `UP` flag in
/// its `<…>` set — `LOWER_UP` alone (carrier, no admin up) does not count.
fn link_is_up(link: &str) -> bool {
    link.split_once('<')
        .and_then(|(_, rest)| rest.split_once('>'))
        .is_some_and(|(flags, _)| flags.split(',').any(|f| f == "UP"))
}

async fn wait_for_device_gone(timeout: Duration) -> anyhow::Result<()> {
    let deadline = tokio::time::Instant::now() + timeout;
    while device_exists(DEVICE)? {
        if tokio::time::Instant::now() >= deadline {
            anyhow::bail!("TUN device {DEVICE} still present {timeout:?} after the proxy exited");
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    Ok(())
}

/// The kernel must pick the TUN device for the fake IP — otherwise the
/// workload measures some other path.
fn ensure_routed_into_device(ip: Ipv4Addr) -> anyhow::Result<()> {
    let out = run_ip(&["route", "get", &ip.to_string()])?;
    anyhow::ensure!(
        out.split_whitespace()
            .collect::<Vec<_>>()
            .windows(2)
            .any(|w| w == ["dev", DEVICE]),
        "{ip} is not routed into {DEVICE}: {}",
        out.trim()
    );
    Ok(())
}

/// User + system CPU seconds the process has consumed, all threads.
fn cpu_seconds(pid: u32) -> anyhow::Result<f64> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat"))?;
    // `comm` (field 2) is parenthesised and may contain spaces — split
    // after its closing paren. The remainder starts at field 3 (state),
    // so utime (14) and stime (15) sit at indices 11 and 12.
    let rest = stat
        .rsplit_once(')')
        .map(|(_, rest)| rest)
        .ok_or_else(|| anyhow::anyhow!("malformed /proc/{pid}/stat"))?;
    let fields: Vec<&str> = rest.split_whitespace().collect();
    let tick = |i: usize| -> anyhow::Result<u64> {
        fields
            .get(i)
            .ok_or_else(|| anyhow::anyhow!("/proc/{pid}/stat: missing field {}", i + 3))?
            .parse()
            .map_err(|e| anyhow::anyhow!("/proc/{pid}/stat field {}: {e}", i + 3))
    };
    // SAFETY: sysconf has no preconditions.
    let hz = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    anyhow::ensure!(hz > 0, "sysconf(_SC_CLK_TCK) failed");
    Ok((tick(11)? + tick(12)?) as f64 / hz as f64)
}

fn render_markdown(report: &TunReport) -> Result<String, std::fmt::Error> {
    use std::fmt::Write as _;

    fn row(
        md: &mut String,
        targets: &[TunTargetResult],
        label: &str,
        cell: &dyn Fn(&TunTargetResult) -> String,
    ) -> std::fmt::Result {
        let cells: Vec<String> = targets.iter().map(cell).collect();
        writeln!(md, "| {label} | {} |", cells.join(" | "))
    }

    let targets = &report.targets;
    let mut md = String::new();
    writeln!(
        md,
        "TUN inbound, MTU {}, fake-ip → DIRECT (loopback echo)\n",
        report.mtu
    )?;
    let names: Vec<&str> = targets.iter().map(|t| t.target.as_str()).collect();
    writeln!(md, "| Metric | {} |", names.join(" | "))?;
    writeln!(md, "|--------|{}", "------|".repeat(targets.len()))?;

    let mb = |b: u64| format!("{:.1} MB", b as f64 / 1_048_576.0);
    row(&mut md, targets, "RSS idle", &|t| mb(t.rss_idle_bytes))?;
    row(&mut md, targets, "RSS under load (peak)", &|t| {
        mb(t.rss_load_bytes)
    })?;
    let labels: Vec<&str> = targets
        .first()
        .map(|t| t.throughput.iter().map(|r| r.label.as_str()).collect())
        .unwrap_or_default();
    for label in labels {
        row(
            &mut md,
            targets,
            &format!("TCP throughput, {label}"),
            &|t| {
                t.throughput
                    .iter()
                    .find(|r| r.label == label)
                    .map_or_else(|| "N/A".to_string(), |r| format!("{:.2} Gbps", r.gbps))
            },
        )?;
    }
    row(&mut md, targets, "Proxy CPU per GB relayed", &|t| {
        format!("{:.3} s", t.throughput_cpu_secs_per_gb)
    })?;
    let parallel_label = targets
        .first()
        .map_or_else(String::new, |t| t.parallel.label.clone());
    row(
        &mut md,
        targets,
        &format!("TCP throughput, {parallel_label}"),
        &|t| format!("{:.2} Gbps", t.parallel.gbps),
    )?;
    row(
        &mut md,
        targets,
        "Proxy CPU per GB relayed (parallel)",
        &|t| format!("{:.3} s", t.parallel_cpu_secs_per_gb),
    )?;
    row(&mut md, targets, "Latency p50 (connect + 1 B echo)", &|t| {
        format!("{:.0} µs", t.latency.p50_us)
    })?;
    row(&mut md, targets, "Latency p95", &|t| {
        format!("{:.0} µs", t.latency.p95_us)
    })?;
    row(&mut md, targets, "Latency p99", &|t| {
        format!("{:.0} µs", t.latency.p99_us)
    })?;
    row(&mut md, targets, "Connections/sec", &|t| {
        format!("{:.0} /s", t.conn_rate.connections_per_sec)
    })?;
    row(&mut md, targets, "Proxy CPU per connection", &|t| {
        format!("{:.0} µs", t.connrate_cpu_us_per_conn)
    })?;
    Ok(md)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn link_up_needs_the_admin_flag() {
        assert!(link_is_up(
            "7: rillbench0: <POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP> mtu 1500 qdisc fq_codel"
        ));
        assert!(!link_is_up(
            "7: rillbench0: <POINTOPOINT,MULTICAST,NOARP,LOWER_UP> mtu 1500 qdisc noop"
        ));
        assert!(!link_is_up("garbage"));
    }

    #[test]
    fn cpu_seconds_reads_own_process() {
        // Burn a little CPU so the reading cannot be a parse that
        // silently lands on a zero field.
        let start = std::time::Instant::now();
        let mut x = 0u64;
        while start.elapsed() < Duration::from_millis(50) {
            x = x.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
        }
        std::hint::black_box(x);
        let secs = cpu_seconds(std::process::id()).unwrap();
        assert!(secs > 0.0, "cpu_seconds returned {secs}");
    }

    #[test]
    fn configs_differ_only_where_the_binaries_do() {
        let upstream: SocketAddr = "127.0.0.1:5300".parse().unwrap();
        let rill = config_yaml(&Flavor::Rill, 9000, upstream);
        let mihomo = config_yaml(
            &Flavor::Mihomo {
                stack: "system".to_string(),
            },
            9000,
            upstream,
        );
        // rill takes the scalar form, mihomo the list form.
        assert!(rill.contains(&format!("inet4-address: {TUN_ADDR}\n")));
        assert!(mihomo.contains(&format!("inet4-address:\n    - {TUN_ADDR}\n")));
        assert!(mihomo.contains("stack: system\n"));
        for cfg in [&rill, &mihomo] {
            assert!(cfg.contains("mtu: 9000\n"));
            assert!(cfg.contains("auto-route: false\n"));
            assert!(cfg.contains("enhanced-mode: fake-ip\n"));
            assert!(cfg.contains("udp://127.0.0.1:5300"));
        }
    }
}
