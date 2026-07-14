# quic-go MASQUE patches (inventory)

При изменении `replace/quic-go-patched/` включать этот diff в описание PR.

| Файл | Назначение |
|------|------------|
| `http3/frames_masque.go` | `EnableMasqueConnectStream` — fast tunnel DATA parse |
| `http3/stream.go` | per-Write DATA frame; `WriteTo` plain Read loop (Invisv) |
| `masque_wake.go` | CONNECT-UDP/IP only: `MasqueWakeConnSend*` |
| `internal/flowcontrol/masque_threshold.go` | optional eager WINDOW (CONNECT-UDP) |

## CONNECT-stream (Invisv thin)

- **Нет** wake/duplex/fair-defer/coalesce/AggressiveCC
- Client: `HTTPStreamer` → `*http3.Stream` → `h3.TunnelConn` (deadlines/context only)
- Server: `relay_h3.go` plain `io.CopyBuffer` 64 KiB

## CONNECT-UDP / CONNECT-IP (KEEP)

- `MasqueWakeConnSend` / `MasqueWakeConnSendDatagramCoalesced`
- Datagram send batching in `http3/conn.go`
