---
icon: material/new-box
---

!!! question "Hiddify fork extension"

    Requires build tag `with_masque` (enabled by default in this fork's `make` and hiddify-core builds).

### Structure

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

  ... // Dial Fields
}
```

Server example:

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

### Types

| `type` | Description |
|--------|-------------|
| `masque` | Generic MASQUE endpoint (client or server). |
| `warp_masque` | WARP-compatible MASQUE profile (extends `masque` options). |

### Fields

#### role

`client` (default) or `server`.

#### mode

Client dataplane mode:

| Value | UDP | TCP |
|-------|-----|-----|
| empty / `default` | CONNECT-UDP | CONNECT-stream |
| `connect_ip` | CONNECT-IP | TCP via CONNECT-IP netstack |

#### http_layer

Client-only external HTTP stack to the MASQUE server: `h3` (default), `h2`, or `auto`.

#### outbound_tls

Client TLS to the MASQUE server (same schema as [Outbound TLS](/configuration/shared/tls/)).

#### tls

Server inbound TLS (same schema as other inbounds). Required when `role` is `server`.

#### template_udp / template_ip / template_tcp

URI templates for CONNECT-UDP, CONNECT-IP, and CONNECT-stream. Path-only forms (e.g. `/masque/udp/{target_host}/{target_port}`) are prefixed with `https://<authority>` automatically.

### Build

MASQUE is compiled in when the binary is built with `-tags with_masque`. Without the tag, config types `masque` and `warp_masque` are registered but fail at runtime with an explicit error.

See also: [Build from source — with_masque](/installation/build-from-source#build-tags).

For full field reference, WARP bootstrap, auth, and chain hops, see the project guide [MASQUE sing-box config](https://github.com/hiddify/hiddify-app/blob/main/docs/masque/MASQUE-SINGBOX-CONFIG.md) (hiddify-app repo).
