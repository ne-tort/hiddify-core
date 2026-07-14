# quic-go MASQUE patches (inventory)

При изменении `replace/quic-go-patched/` включать этот diff в описание PR.  
Stack policy: [`docs/masque/ADR-QUIC-STACK-OVERLAY.md`](../../../../docs/masque/ADR-QUIC-STACK-OVERLAY.md).

| Файл / area | Назначение |
|-------------|------------|
| `http3/frames_masque.go` | `EnableMasqueConnectStream` — fast tunnel DATA parse |
| `http3/stream.go` | per-Write DATA; `WriteTo` plain Read; UDP/IP datagram helpers |
| `http3/body.go` | Client `HTTPStreamer` / `ReleaseHTTPStream` / deadlines (**CRITICAL** CONNECT) |
| `masque_wake.go` | CONNECT-UDP/IP only: `MasqueWakeConnSend*` |
| `congestion/`, `monotime/` | Public CC API (sagernet port) |
| `internal/ackhandler/cc_adapter*.go` + SPH Ex | `SetCongestionControl` / `OnCongestionEventEx` / `MaybeNotifyAppLimited` |
| `Config.CongestionControl` + `populateConfig` | `new_reno`\|`cubic`\|`bbr*` selection (advanced swapped post-dial) |
| `internal/congestion/cubic_sender.go` | ICWND=192 for CubicSender path |

## Congestion (post-dial)

`transport/masque/h3.ApplyCongestionControl` + vendored:

- `transport/masque/congestion_meta2` → `bbr` (**default**)
- `transport/masque/congestion_bbr2` → `bbr2` / `bbr2_aggressive`

Не мигрировать wholesale на `sagernet/quic-go` ради CC — см. ADR.

## CONNECT-stream (Invisv thin)

- **Нет** wake/duplex/fair-defer/coalesce/AggressiveCC / Dual/stripe
- Client: `HTTPStreamer` → `*http3.Stream` → `h3.TunnelConn`
- Server: `relay_h3.go` plain `io.CopyBuffer` 64 KiB
- Mux: many CONNECT streams / one shared QUIC (`TCPHTTP`)

## CONNECT-UDP / CONNECT-IP (KEEP)

- `MasqueWakeConnSend` / `MasqueWakeConnSendDatagramCoalesced`
- Datagram send batching
