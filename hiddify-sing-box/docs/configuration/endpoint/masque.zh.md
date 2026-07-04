---
icon: material/new-box
---

!!! question "Hiddify 分支扩展"

    需要构建标记 `with_masque`（本分支 `make` 与 hiddify-core 构建默认启用）。

### 结构

```json
{
  "type": "masque",
  "tag": "masque-ep",
  "role": "client",
  "server": "example.com",
  "server_port": 443,
  "mode": "default",
  "http_layer": "h3",
  "outbound_tls": {
    "enabled": true,
    "server_name": "example.com"
  },

  ... // 拨号字段
}
```

服务端示例：

```json
{
  "type": "masque",
  "tag": "masque-srv",
  "role": "server",
  "listen": "::",
  "listen_port": 443,
  "tls": {
    "enabled": true,
    "certificate_path": "cert.pem",
    "key_path": "key.pem"
  }
}
```

### 类型

| `type` | 说明 |
|--------|------|
| `masque` | 通用 MASQUE 端点（客户端或服务端）。 |
| `warp_masque` | WARP 兼容 MASQUE 配置（扩展 `masque` 选项）。 |

### 字段

#### role

`client`（默认）或 `server`。

#### mode

客户端数据面模式：

| 值 | UDP | TCP |
|----|-----|-----|
| 空 / `default` | CONNECT-UDP | CONNECT-stream |
| `connect_ip` | CONNECT-IP | 经 CONNECT-IP netstack 的 TCP |

#### http_layer

仅客户端：到 MASQUE 服务端的外层 HTTP 栈：`h3`（默认）、`h2` 或 `auto`。

#### outbound_tls

客户端到 MASQUE 服务端的 TLS（与 [出站 TLS](/zh/configuration/shared/tls/) 相同 schema）。

#### tls

服务端入站 TLS（与其他 inbound 相同）。`role: server` 时必需。

#### template_udp / template_ip / template_tcp

CONNECT-UDP、CONNECT-IP、CONNECT-stream 的 URI 模板。仅路径形式（如 `/masque/udp/{target_host}/{target_port}`）会自动加上 `https://<authority>` 前缀。

### 构建

使用 `-tags with_masque` 编译时启用 MASQUE。未带该标记时，`masque` 与 `warp_masque` 类型仍注册，但运行时会明确报错。

另见：[从源代码构建 — with_masque](/zh/installation/build-from-source#构建标记)。

完整字段、WARP bootstrap、认证与链式 hop 见项目文档 [MASQUE sing-box config](https://github.com/hiddify/hiddify-app/blob/main/docs/masque/MASQUE-SINGBOX-CONFIG.md)（hiddify-app 仓库）。
