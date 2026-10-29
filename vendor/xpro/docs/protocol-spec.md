# XPro/1 线协议 v1

本文冻结本实现的线格式。所有整数无符号、网络字节序；所有字符串按原始 ASCII/UTF-8 字节计长，不含 NUL 终止符。不支持版本协商、可选操作、扩展标志或 UDP。修改编码需递增版本，禁止宽松猜测。

## 传输

直连为 TLS 1.3（ALPN `h2`）上的 HTTP/2 POST `/api/stream` 双向流。authority 包括非 443 端口；所有签名字符串必须与配置一致，不自动改写大小写、路径、转义或 query。准入及 OPEN 使用同一外层 TLS 通道绑定。一个目标占一个 H2 stream。

CDN 为 HTTP/1.1 WebSocket GET Upgrade（外层 TLS 1.3），二进制消息构成有序字节流，单消息/单帧上限 64 KiB，无压缩及其他扩展。字节流承载第二个 TLS 1.3；OPEN 使用内层 exporter。客户端只信任配置的私有 CA，校验固定名称 `xpro-origin`。不使用 RFC 8441、0-RTT 或 early exporter。

通道绑定为 RFC 9266：普通 TLS exporter，label `EXPORTER-Channel-Binding`，context 为长度 0 的字节串，输出 32 字节。代码使用 `Some(&[])`，与独立 rustls 测试端互操作。参考：[RFC 9266](https://www.rfc-editor.org/rfc/rfc9266.html)。

## HTTP 准入证明

唯一请求头 `x-xpro-admission` 为以下 74 字节的 148 个十六进制字符。客户端输出小写；服务端接受十六进制大小写。重复头拒绝。客户端 HeaderValue 标记敏感，禁止 HPACK 索引。

|偏移|长度|字段|
|---|---:|---|
|0|1|version = 1|
|1|1|profile：H2 = 1，WSS = 2|
|2|16|device ID|
|18|8|Unix timestamp，秒|
|26|16|随机 nonce|
|42|32|HMAC-SHA256|

`prefix` 是前 42 字节。准入 HMAC 输入依序为：

```
ASCII("XPro/1 admission") || 00 || prefix ||
u16(authority.len) || authority ||
u16(method.len) || method ||
u16(path.len) || path ||
[32-byte outer exporter, 仅 H2]
```

H2 必须为 POST + HTTP/2，WSS 必须为 GET + HTTP/1.1。WSS 准入不含任何目标信息。缺失、错误、过期、重放、错 authority、错 path 的证明走同一真实网站 handler；不返回专属认证错误。

## 帧

```
type:u8 || flags:u8(必须为0) || payload_length:u32 || payload
```

|type|消息|载荷及约束|
|---:|---|---|
|1|AUTH_OPEN|1..4096 字节，仅客户端首帧|
|2|CONNECTED|0 字节，仅服务端、目标 TCP 建立后|
|3|DATA|1..16384 字节，仅 CONNECTED 后|
|4|HALF_CLOSE|0 字节，每端最多一次|
|5|CLOSE|0 字节，双向 HALF_CLOSE 后|
|6|ERROR|2 字节受控错误码，仅认证后服务端|

头部全部验证后才分配载荷。未知类型、非零 flags、非法载荷长度、重复控制帧、DATA 出现在对端 HALF_CLOSE 后、第二次 AUTH_OPEN、CONNECTED 重复均终止流。原始传输 EOF、RST、TLS 截断不会当作 TCP 正常 EOF。

目标编码：

|标识|格式|
|---:|---|
|1|4 字节 IPv4 + u16 port|
|2|16 字节 IPv6 + u16 port|
|3|u8 domain_length + domain bytes + u16 port|

port 不得为 0。域名最大 253 字节，小写 ASCII A-label，每个 label 1..63 字节，字母、数字、内部连字符；无尾随点或空 label。rill 客户端使用 IDNA 将国际化域名转换为 A-label；协议库拒绝非规范形式。IPv4/IPv6 地址由数值字节编码，无 DNS 再解析。

AUTH_OPEN 载荷为新的 `proof(74 bytes) || encoded_destination`，新 nonce，profile/device 与准入相同。其 MAC 输入：

```
ASCII("XPro/1 open") || 00 || prefix ||
32-byte exporter || encoded_destination
```

OPEN 域分离同时限定 TCP 操作。H2 的 exporter 来自外层 TLS；WSS 来自内层 TLS。认证、重放检查及全局/设备额度通过前，不允许解析目标 DNS 或建立出站连接。客户端在 CONNECTED 前不交付应用流。当前 ERROR `0001` 表示认证通过后的目标建立失败，不包含 DNS、地址或内部细节。

时间窗为服务端当前时间 ±60 秒（边界包含）。两个阶段独立 nonce、独立域分离。重放键为 `(stage, device_id, nonce)`，跨配置档共享索引；先验 MAC，后在互斥临界区登记；并发相同 nonce 最多成功一次。使用单调时钟保存至少 180 秒，不提前驱逐；容量满拒绝认证。进程重启不会持久化重放状态，因此本版仅支持单实例；WSS 首阶段在重启时间窗内的重放仍不能通过内层 OPEN 通道绑定。

## 状态与关闭

`准入 -> 安全流 -> AUTH_OPEN -> 认证/重放/额度/ACL/目标 TCP -> CONNECTED -> DATA/HALF_CLOSE -> CLOSE`。

HALF_CLOSE 表示发送方没有更多 DATA，接收方对应用暴露该方向 EOF；另一方向继续传输。AsyncWrite flush 等待已接收 DATA 交给传输写入；shutdown 需等待排队 DATA 和 HALF_CLOSE 写出。双方半关闭后各发送 CLOSE，关闭传输写方向；等待 CLOSE 最多 5 秒。读到 HALF_CLOSE 后若本地已经关闭写方向，读取 EOF 前等待 CLOSE 收尾；服务器转发完成也等待收尾。主动丢弃应用连接会取消会话。异常不自动重放应用数据。

## 黄金向量

[tests/golden-vectors.txt](../tests/golden-vectors.txt) 由独立 Python `struct` + `hmac/hashlib` 生成，协议测试比对逐字节输入及 MAC。

- key = `33` 重复 32 次，device = `11` 重复 16 次，nonce = `22` 重复 16 次。
- version/profile = `01/01`，timestamp = `1700000000`，exporter = `44` 重复 32 次。
- 准入绑定 `direct.example.com` / `POST` / `/api/stream`。
- 目标 `example.com:443`，编码 `030b6578616d706c652e636f6d01bb`。
- 第 1/2 行为准入输入/MAC，第 3/4 行为 OPEN 输入/MAC。
