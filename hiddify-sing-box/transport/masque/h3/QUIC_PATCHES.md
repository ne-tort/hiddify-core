# quic-go MASQUE patches (inventory)

При изменении `replace/quic-go-patched/` включать этот diff в описание PR.

| Файл | Назначение |
|------|------------|
| `masque_wake.go` | `MasqueWakeStreamSend`, `MasqueWakeConnSend` — scheduler nudge |
| `http3/masque_wake.go` | `masqueWakeSendOnReceiveRead`, `masqueWakeSendAfterReceiveRead` |
| `http3/client.go` | `ClientConn.MasqueWakeSend()` → `MasqueWakeConnSend` |
| `http3/body.go` | wake after response `Read` (gated by env) |
| `http3/state_tracking_stream.go` | stream `Read` wake gated by `MASQUE_QUIC_WAKE_SEND_ON_RECEIVE_READ` |

Env: `MASQUE_QUIC_WAKE_SEND_ON_RECEIVE_READ=0` отключает conn-wide `MasqueWakeStreamSend` при bidi bulk localize (CONNECT-stream upload на том же QUIC connection). CONNECT-IP ingress ACK wake — отдельно через `h3.FlushConnectIPIngressAckWake`.
