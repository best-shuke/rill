# rill

用 Rust 写的代理内核，兼容 [mihomo](https://github.com/MetaCubeX/mihomo)（Clash Meta）的配置和控制接口，是 [FlowBar](https://github.com/best-shuke/FlowBar) 的内核。

目标是在 FlowBar 的用法下和 mihomo 效果一致，同时更轻、更快：

- **配置兼容**：mihomo 的 YAML 配置直接使用，节点、策略组、规则、DNS、rule / proxy providers 原样生效。
- **TUN 接管全部流量**：macOS、Linux、Windows，行为对齐 mihomo 的 `tun` 段。
- **轻量**：常驻内存约为 mihomo 的三分之一，二进制更小。
- **快**：TUN 下多连接并发吞吐是 mihomo `system` 栈的 2.4–2.6 倍（[基准](docs/benchmarks/tun-inbound-2026-10.md)）。

## 状态

早期开发中。已经可用：

- 出站：Shadowsocks（含 2022）、VMess、VLESS（Vision / Reality）、Trojan、Hysteria2、AnyTLS、Snell、HTTP、SOCKS5
- 策略组：select、url-test、fallback、load-balance、relay，以及 `dialer-proxy` 链
- 规则：DOMAIN 系列、GEOIP、GEOSITE、IP-ASN、RULE-SET、逻辑规则、SUB-RULE、进程规则等
- DNS：fake-ip、DoH、DoT、nameserver-policy、fallback-filter、hosts
- 入站：mixed / HTTP / SOCKS5、TProxy、TUN
- REST API：mihomo 兼容的 `/proxies`、`/configs`、`/version` 等

正在做（按优先级）：

1. TUN 与 mihomo 行为对齐：`auto-route` 全局接管、`strict-route`、`route-exclude-address`、跟随网络切换、TCP DNS 劫持、不改系统 DNS
2. Geo 数据库与 mihomo 一致：`geoip.metadb`、`GeoIP.dat`（`geodata-mode`）、校验阶段下载
3. 补齐协议：TUIC、WireGuard、Hysteria、SSR 等

和 mihomo 的已知差异见 [docs/migration-from-go-mihomo.md](docs/migration-from-go-mihomo.md)。

## 构建

需要 Rust 1.89+、cmake 和 C++ 编译器（BoringSSL）。

```sh
cargo build --release
./target/release/rill -f config.yaml        # 运行
./target/release/rill -f config.yaml -t     # 只检查配置
./target/release/rill-cli status            # 控制正在运行的 rill
```

测试和提交前检查见 [CLAUDE.md](CLAUDE.md) 的 Regression Bar 一节。

## 来源与许可

rill 派生自 [meow-rs](https://github.com/meow-rs/meow-rs)（MIT），从它的 `62525d4` 起独立开发。MIT 许可证，见 [LICENSE](LICENSE)；来源和第三方组件说明见 [NOTICE](NOTICE)。
