//! The built `rill-cli` binary against the real rill-api router, the way a
//! user runs it: over TCP, with the API secret, reading what it prints.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use dashmap::DashMap;
use parking_lot::RwLock;
use rill_api::log_stream::{LogLevel, LogMessage};
use rill_api::routes::{create_router, AppState};
use rill_common::{controller_file, DnsMode};
use rill_dns::Resolver;
use rill_trie::DomainTrie;
use rill_tunnel::Tunnel;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::process::Command;
use tokio::sync::broadcast;

const SECRET: &str = "s3cret";

const CONFIG: &str = r#"
mode: rule
log-level: info
proxy-groups:
  - name: "节点选择"
    type: select
    proxies: [DIRECT, REJECT]
  - name: Auto
    type: url-test
    proxies: [DIRECT, REJECT]
    url: https://www.gstatic.com/generate_204
    interval: 300
rules:
  - DOMAIN,example.com,节点选择
  - MATCH,DIRECT
"#;

/// The API, served on a loopback port as rill serves it.
struct Rill {
    addr: SocketAddr,
    state: Arc<AppState>,
    dir: tempfile::TempDir,
}

impl Rill {
    async fn start() -> Self {
        Self::start_with(CONFIG).await
    }

    async fn start_with(config: &str) -> Self {
        let raw = rill_config::parse_raw_yaml(config).unwrap();
        let resolver = Arc::new(Resolver::new(
            vec!["8.8.8.8:53".parse().unwrap()],
            vec![],
            DnsMode::Normal,
            DomainTrie::new(),
            true,
            true,
        ));
        let tunnel = Tunnel::new(resolver);
        let rill_config::RebuildResult { proxies, rules, .. } =
            rill_config::rebuild_from_raw(&raw).unwrap();
        tunnel.update_proxies(proxies, Default::default());
        tunnel.update_rules(rules);

        let dir = tempfile::tempdir().unwrap();
        let state = Arc::new(AppState {
            tunnel,
            secret: Some(SECRET.into()),
            config_path: Some(dir.path().join("config.yaml").display().to_string()),
            raw_config: Arc::new(RwLock::new(raw)),
            log_tx: broadcast::channel(16).0,
            proxy_providers: Arc::new(DashMap::new()),
            provider_dialer_registry: Default::default(),
            rule_providers: Arc::new(RwLock::new(HashMap::new())),
            rule_provider_refresh: Default::default(),
            proxy_provider_refresh: Default::default(),
            listeners: vec![],
            external_ui: None,
            traffic_feed: Default::default(),
            dns_server: Default::default(),
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let router = create_router(Arc::clone(&state));
        tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        Self { addr, state, dir }
    }

    /// `rill-cli` aimed at this rill through the environment.
    fn cli(&self, args: &[&str]) -> Command {
        let mut command = bare_cli(args);
        command
            .env("RILL_CONTROLLER", self.addr.to_string())
            .env("RILL_SECRET", SECRET);
        command
    }

    async fn run(&self, args: &[&str]) -> String {
        succeeds(self.cli(args), args).await
    }

    async fn fails(&self, args: &[&str]) -> String {
        fails(self.cli(args), args).await
    }

    /// A config file rill-cli can read the controller and secret from.
    fn config_file(&self, rules: &[&str]) -> PathBuf {
        let mut text = format!(
            "external-controller: :{}\nsecret: {SECRET}\n{}",
            self.addr.port(),
            CONFIG.split("rules:").next().unwrap()
        );
        text.push_str("rules:\n");
        for rule in rules {
            text.push_str("  - ");
            text.push_str(rule);
            text.push('\n');
        }
        let path = self.dir.path().join("rill.yaml");
        std::fs::write(&path, text).unwrap();
        path
    }
}

/// `rill-cli` with none of the caller's `RILL_*` settings, and blind to
/// any rill running on this machine.
fn bare_cli(args: &[&str]) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_rill-cli"));
    command
        .args(args)
        .env_remove("RILL_CONTROLLER")
        .env_remove("RILL_CONFIG")
        .env_remove("RILL_SECRET")
        .env(
            controller_file::DIR_ENV,
            Path::new(env!("CARGO_TARGET_TMPDIR")).join("no-rill-running"),
        )
        .stdin(Stdio::null())
        .kill_on_drop(true);
    command
}

async fn output(mut command: Command) -> std::process::Output {
    tokio::time::timeout(Duration::from_secs(30), command.output())
        .await
        .expect("rill-cli did not finish")
        .unwrap()
}

async fn succeeds(command: Command, args: &[&str]) -> String {
    let out = output(command).await;
    let stdout = String::from_utf8(out.stdout).unwrap();
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(
        out.status.success(),
        "rill-cli {args:?} failed: {stderr}\nstdout: {stdout}"
    );
    stdout
}

async fn fails(command: Command, args: &[&str]) -> String {
    let out = output(command).await;
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert_eq!(
        out.status.code(),
        Some(1),
        "rill-cli {args:?} should fail; stdout: {}",
        String::from_utf8_lossy(&out.stdout)
    );
    stderr
}

fn json(text: &str) -> serde_json::Value {
    serde_json::from_str(text).unwrap_or_else(|e| panic!("not JSON ({e}): {text}"))
}

#[tokio::test(flavor = "multi_thread")]
async fn status_reads_the_running_config() {
    let rill = Rill::start().await;
    let text = rill.run(&["status"]).await;
    assert!(text.starts_with("rill "), "{text}");
    assert!(text.contains(&format!(" at {}", rill.addr)), "{text}");
    assert!(text.contains("mode         rule"), "{text}");
    assert!(text.contains("connections  0 open"), "{text}");

    let status = json(&rill.run(&["status", "--json"]).await);
    assert_eq!(status["configs"]["mode"], "rule");
    assert_eq!(status["connections"], 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_missing_secret_says_how_to_give_it() {
    let rill = Rill::start().await;
    let mut command = bare_cli(&["status"]);
    command.env("RILL_CONTROLLER", rill.addr.to_string());
    let stderr = fails(command, &["status"]).await;
    assert!(
        stderr.contains("rill wants the API secret (401)"),
        "{stderr}"
    );
    assert!(!stderr.contains(SECRET));
}

#[tokio::test(flavor = "multi_thread")]
async fn the_secret_can_come_from_stdin() {
    let rill = Rill::start().await;
    let mut command = bare_cli(&["--secret-stdin", "mode"]);
    command
        .env("RILL_CONTROLLER", rill.addr.to_string())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped());
    let mut child = command.spawn().unwrap();
    let mut stdin = child.stdin.take().unwrap();
    stdin
        .write_all(format!("{SECRET}\n").as_bytes())
        .await
        .unwrap();
    drop(stdin);
    let out = tokio::time::timeout(Duration::from_secs(30), child.wait_with_output())
        .await
        .unwrap()
        .unwrap();
    assert!(out.status.success());
    assert_eq!(String::from_utf8(out.stdout).unwrap(), "rule\n");
}

#[tokio::test(flavor = "multi_thread")]
async fn an_unreachable_controller_is_named() {
    // A port nothing listens on: bind one, then free it.
    let free = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = free.local_addr().unwrap();
    drop(free);
    let mut command = bare_cli(&["status"]);
    command.env("RILL_CONTROLLER", addr.to_string());
    let stderr = fails(command, &["status"]).await;
    assert!(
        stderr.contains(&format!("cannot reach rill's controller at {addr}")),
        "{stderr}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_selector_switches_and_shows_its_choice() {
    let rill = Rill::start().await;
    let list = rill.run(&["group", "list"]).await;
    assert!(list.contains("节点选择 -> DIRECT"), "{list}");

    let text = rill.run(&["group", "select", "节点选择", "REJECT"]).await;
    assert_eq!(text, "节点选择 -> REJECT\n");
    let show = json(&rill.run(&["--json", "group", "show", "节点选择"]).await);
    assert_eq!(show["now"], "REJECT");
    let show = rill.run(&["group", "show", "节点选择"]).await;
    assert!(show.contains("*  "), "{show}");

    let stderr = rill.fails(&["group", "select", "节点选择", "nope"]).await;
    assert!(stderr.contains("rill answered 400"), "{stderr}");
    let stderr = rill.fails(&["group", "unfix", "节点选择"]).await;
    assert!(
        stderr.contains("only url-test and fallback groups"),
        "{stderr}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn an_automatic_group_pins_and_unpins() {
    let rill = Rill::start().await;
    let text = rill.run(&["group", "select", "Auto", "REJECT"]).await;
    assert_eq!(text, "Auto -> REJECT (pinned)\n");
    let show = json(&rill.run(&["--json", "group", "show", "Auto"]).await);
    assert_eq!(show["fixed"], "REJECT");

    let text = rill.run(&["group", "unfix", "Auto"]).await;
    assert!(!text.contains("pinned"), "{text}");
    let show = json(&rill.run(&["--json", "group", "show", "Auto"]).await);
    assert_eq!(show["fixed"], "");
}

#[tokio::test(flavor = "multi_thread")]
async fn mode_and_log_level_switch_in_memory() {
    let rill = Rill::start().await;
    assert_eq!(rill.run(&["mode"]).await, "rule\n");
    assert_eq!(rill.run(&["mode", "global"]).await, "global\n");
    assert_eq!(rill.run(&["mode"]).await, "global\n");
    assert_eq!(
        json(&rill.run(&["--json", "mode", "direct"]).await),
        serde_json::json!({ "mode": "direct" })
    );

    assert_eq!(rill.run(&["log-level", "warning"]).await, "warning\n");
    assert_eq!(rill.run(&["log-level"]).await, "warning\n");
    // `--json` is global: it may follow the subcommand.
    let level = json(&rill.run(&["log-level", "--json"]).await);
    assert_eq!(level["log-level"], "warning");
}

#[tokio::test(flavor = "multi_thread")]
async fn rules_list_in_match_order() {
    let rill = Rill::start().await;
    let text = rill.run(&["rule", "list"]).await;
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.len(), 3, "{text}");
    assert!(lines[1].contains("example.com") && lines[1].ends_with("节点选择"));
    assert!(lines[2].starts_with("1 "), "{text}");

    let filtered = rill.run(&["rule", "list", "--filter", "EXAMPLE"]).await;
    assert_eq!(filtered.lines().count(), 2, "{filtered}");
    let rules = json(&rill.run(&["--json", "rule", "list"]).await);
    assert_eq!(rules["rules"].as_array().unwrap().len(), 2);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_config_file_names_the_controller_and_reloads() {
    let rill = Rill::start().await;
    let config = rill.config_file(&[
        "DOMAIN,example.com,节点选择",
        "DOMAIN-SUFFIX,example.org,Auto",
        "MATCH,DIRECT",
    ]);
    let config = config.to_str().unwrap();

    // `external-controller: :PORT` reaches the loopback; the secret comes
    // from the same file.
    let text = succeeds(bare_cli(&["--config", config, "mode"]), &["mode"]).await;
    assert_eq!(text, "rule\n");

    let text = succeeds(bare_cli(&["--config", config, "reload"]), &["reload"]).await;
    assert_eq!(text, format!("reloaded {config}\n"));
    let rules = rill.run(&["rule", "list", "--filter", "example.org"]).await;
    assert!(
        rules.contains("DOMAIN-SUFFIX  example.org  Auto"),
        "{rules}"
    );

    // A config that does not parse is refused and the old one stays.
    let broken = rill.dir.path().join("broken.yaml");
    std::fs::write(&broken, "rules: [unclosed\n").unwrap();
    let stderr = rill.fails(&["reload", broken.to_str().unwrap()]).await;
    assert!(stderr.contains("rill answered 400"), "{stderr}");
    let rules = json(&rill.run(&["--json", "rule", "list"]).await);
    assert_eq!(rules["rules"].as_array().unwrap().len(), 3);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_config_without_a_controller_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let path: &Path = &dir.path().join("plain.yaml");
    std::fs::write(path, "mixed-port: 7890\n").unwrap();
    let stderr = fails(
        bare_cli(&["--config", path.to_str().unwrap(), "status"]),
        &["status"],
    )
    .await;
    assert!(stderr.contains("sets no external-controller"), "{stderr}");
}

#[tokio::test(flavor = "multi_thread")]
async fn the_running_rill_is_found_without_options() {
    let rill = Rill::start().await;
    let config = rill.config_file(&["DOMAIN-SUFFIX,example.org,Auto", "MATCH,DIRECT"]);
    // What rill publishes once its external-controller is bound.
    let runtime = rill.dir.path().join("controllers");
    let _published =
        controller_file::publish_in(&runtime, rill.addr, Some(SECRET), Some(&config)).unwrap();
    let found = |args: &[&str]| {
        let mut command = bare_cli(args);
        command.env(controller_file::DIR_ENV, &runtime);
        command
    };

    let text = succeeds(found(&["status"]), &["status"]).await;
    assert!(text.contains(&format!(" at {}", rill.addr)), "{text}");

    // `reload` loads the config that rill loaded.
    let text = succeeds(found(&["reload"]), &["reload"]).await;
    assert_eq!(text, format!("reloaded {}\n", config.display()));
    let rules = rill.run(&["rule", "list", "--filter", "example.org"]).await;
    assert!(
        rules.contains("DOMAIN-SUFFIX  example.org  Auto"),
        "{rules}"
    );

    // An address given by hand gets the secret rill published for it.
    let mut command = found(&["mode"]);
    command.env("RILL_CONTROLLER", rill.addr.to_string());
    assert_eq!(succeeds(command, &["mode"]).await, "rule\n");

    // With a second rill running, rill-cli names both and picks neither.
    let other = runtime.join("1.json");
    std::fs::write(&other, r#"{"pid":1,"controller":"127.0.0.1:9"}"#).unwrap();
    let lock = std::fs::File::open(&other).unwrap();
    lock.lock_shared().unwrap();
    let stderr = fails(found(&["status"]), &["status"]).await;
    assert!(
        stderr.contains("2 rills are running; choose one with --controller"),
        "{stderr}"
    );
    assert!(stderr.contains(&rill.addr.to_string()), "{stderr}");
    assert!(!stderr.contains(SECRET), "{stderr}");

    // Once that rill is gone its lock is too, and its file is swept.
    drop(lock);
    succeeds(found(&["status"]), &["status"]).await;
    assert!(!other.exists());
}

#[tokio::test(flavor = "multi_thread")]
async fn connections_list_and_close() {
    let rill = Rill::start().await;
    assert_eq!(rill.run(&["conn", "list"]).await, "no open connections\n");
    let list = json(&rill.run(&["--json", "connections", "list"]).await);
    assert_eq!(list, serde_json::json!([]));
    assert_eq!(
        rill.run(&["conn", "close", "--all"]).await,
        "closed every connection\n"
    );
    let stderr = rill.fails(&["conn", "show", "1a2b"]).await;
    assert!(stderr.contains("1a2b"), "{stderr}");
    // rill answers 204 to closing any well-formed id: rill-cli checks first.
    let gone = "0f8e2b1c-5d4a-4c3b-9a2e-7f6d5c4b3a21";
    let stderr = rill.fails(&["conn", "close", gone]).await;
    assert!(stderr.contains(gone), "{stderr}");
    let stderr = rill.fails(&["conn", "close", ""]).await;
    assert!(stderr.contains("connection id"), "{stderr}");
}

#[tokio::test(flavor = "multi_thread")]
async fn dns_cache_and_logbook_read_when_empty() {
    let rill = Rill::start().await;
    assert_eq!(rill.run(&["dns", "cache"]).await, "no cached answers\n");
    let logbook = rill.run(&["logbook"]).await;
    assert!(
        logbook == "no entries\n" || logbook.starts_with("the logbook is off"),
        "{logbook}"
    );
    assert_eq!(rill.run(&["provider", "list"]).await, "no providers\n");
    assert_eq!(
        rill.run(&["subscription", "list"]).await,
        "no subscriptions\n"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn streams_stop_after_count() {
    let rill = Rill::start().await;
    let text = rill.run(&["traffic", "--count", "2", "--json"]).await;
    let samples: Vec<serde_json::Value> = text.lines().map(json).collect();
    assert_eq!(samples.len(), 2, "{text}");
    assert!(samples[0].get("up").is_some(), "{text}");

    // The log stream: feed lines until rill-cli has read the one it waits
    // for. Debug lines sit below `--level info` and never show.
    let log_tx = rill.state.log_tx.clone();
    let feeder = tokio::spawn(async move {
        loop {
            for (level, payload) in [(LogLevel::Debug, "hidden"), (LogLevel::Warning, "shown")] {
                let _ = log_tx.send(LogMessage {
                    level,
                    payload: payload.into(),
                    time: time::OffsetDateTime::now_utc(),
                });
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    });
    let text = rill.run(&["log", "--count", "1"]).await;
    feeder.abort();
    assert_eq!(text, "warning  shown\n");
}

#[tokio::test(flavor = "multi_thread")]
async fn the_skill_prints_itself() {
    let text = succeeds(bare_cli(&["skill"]), &["skill"]).await;
    assert_eq!(text, include_str!("../skills/rill-cli/SKILL.md"));
    // `lines()`: a Windows checkout may turn the file's newlines into CRLF.
    let head: Vec<&str> = text.lines().take(2).collect();
    assert_eq!(head, ["---", "name: rill-cli"]);
}

/// Reads a request head off `stream`: the text up to its blank line.
async fn read_head(stream: &mut tokio::net::TcpStream) -> Option<String> {
    let mut head = Vec::new();
    let mut buf = [0u8; 1024];
    while !head.windows(4).any(|w| w == b"\r\n\r\n") {
        let n = stream.read(&mut buf).await.ok().filter(|&n| n > 0)?;
        head.extend_from_slice(&buf[..n]);
    }
    String::from_utf8(head).ok()
}

/// An HTTP server that answers every request with a 204.
async fn origin() -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                if read_head(&mut stream).await.is_some() {
                    let reply = b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n";
                    let _ = stream.write_all(reply).await;
                }
            });
        }
    });
    addr
}

/// An HTTP CONNECT proxy. It closes every tunnel to port `blocks` without
/// a reply, as a node that audits that server does.
async fn connect_proxy(blocks: Option<u16>) -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let Some(head) = read_head(&mut stream).await else {
                    return;
                };
                let Some(target) = head
                    .strip_prefix("CONNECT ")
                    .and_then(|rest| rest.split_whitespace().next())
                else {
                    return;
                };
                let port = target.rsplit_once(':').and_then(|(_, p)| p.parse().ok());
                if port.is_some() && port == blocks {
                    return;
                }
                let Ok(mut upstream) = tokio::net::TcpStream::connect(target).await else {
                    let _ = stream.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n").await;
                    return;
                };
                let established = b"HTTP/1.1 200 Connection established\r\n\r\n";
                if stream.write_all(established).await.is_ok() {
                    let _ = tokio::io::copy_bidirectional(&mut stream, &mut upstream).await;
                }
            });
        }
    });
    addr
}

/// `daniel`, an HTTP proxy, chained through each member of `third-fast`:
/// real proxies over loopback, the probe fetching from a local server.
#[tokio::test(flavor = "multi_thread")]
async fn chain_health_tells_which_members_carry_a_proxy() {
    let origin = origin().await;
    let daniel = connect_proxy(None).await;
    let clean = connect_proxy(None).await;
    let audited = connect_proxy(Some(daniel.port())).await;
    // A port nothing listens on: bind one, then free it.
    let dead = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let dead_port = dead.local_addr().unwrap().port();
    drop(dead);
    let config = format!(
        r#"
mode: rule
proxies:
  - {{name: daniel, type: http, server: 127.0.0.1, port: {}}}
  - {{name: clean, type: http, server: 127.0.0.1, port: {}}}
  - {{name: audited, type: http, server: 127.0.0.1, port: {}}}
  - {{name: dead, type: http, server: 127.0.0.1, port: {dead_port}}}
proxy-groups:
  - name: Auto
    type: select
    proxies: [DIRECT]
  - name: third-fast
    type: select
    proxies: [dead, audited, Auto, daniel, clean]
rules:
  - MATCH,DIRECT
"#,
        daniel.port(),
        clean.port(),
        audited.port(),
    );
    let rill = Rill::start_with(&config).await;
    let url = format!("http://{origin}/generate_204");
    let args = [
        "chain-health",
        "daniel",
        "third-fast",
        "--url",
        &url,
        "--probe-timeout",
        "3000",
    ];

    // Carriers first, then the members that cannot carry it.
    let text = rill.run(&args).await;
    let rows: Vec<(&str, &str)> = text
        .lines()
        .skip(1)
        .map(|line| {
            let words: Vec<&str> = line.split_whitespace().collect();
            (words[0], *words.last().unwrap())
        })
        .collect();
    assert_eq!(
        rows,
        [
            ("reached", "clean"),
            ("failed", "audited"),
            ("down", "dead"),
            ("skipped", "Auto"),
            ("skipped", "daniel"),
        ],
        "{text}"
    );

    // JSON keeps the group's order.
    let answer = json(&rill.run(&[&["--json"], &args[..]].concat()).await);
    assert_eq!(answer["server"], format!("127.0.0.1:{}", daniel.port()));
    let verdicts: Vec<(&str, &str)> = answer["members"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| (m["name"].as_str().unwrap(), m["verdict"].as_str().unwrap()))
        .collect();
    assert_eq!(
        verdicts,
        [
            ("dead", "down"),
            ("audited", "failed"),
            ("Auto", "skipped"),
            ("daniel", "skipped"),
            ("clean", "reached"),
        ]
    );
    let audited = &answer["members"][1];
    assert!(audited["member-delay"].as_u64().unwrap() > 0, "{answer}");
    assert!(audited["reason"].is_string(), "{answer}");

    // Nothing was recorded.
    let clean = json(&rill.run(&["--json", "proxy", "show", "clean"]).await);
    assert_eq!(clean["history"], serde_json::json!([]), "{clean}");

    let stderr = rill.fails(&["chain-health", "third-fast", "clean"]).await;
    assert!(stderr.contains("'third-fast' is a group"), "{stderr}");
    let stderr = rill.fails(&["chain-health", "nope", "clean"]).await;
    assert!(stderr.contains("no proxy named 'nope'"), "{stderr}");
}
