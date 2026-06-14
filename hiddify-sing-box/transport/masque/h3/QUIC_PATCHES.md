# quic-go MASQUE patches (inventory)

При изменении `replace/quic-go-patched/` включать этот diff в описание PR.

| Файл | Назначение |
|------|------------|
| `masque_wake.go` | `MasqueWakeStreamSend`, `MasqueWakeBidiDuplex`, `MasqueWakeConnSend`, `MasqueSetBidiDownloadActive`, `MasquePokeDownloadReceiveWindow`, `masqueWakeAfterDownloadRead`, `masqueWakeAfterDownloadWrite` |
| `receive_stream.go` | `masquePokeDownloadReceiveWindow` — queue MAX_STREAM_DATA + `onHasStreamControlFrame` when download leg starts (before/between Reads; avoids 64 KiB/RTT stall) |
| `masque_framer.go` | bidi download-active queue front (`MASQUE_QUIC_BIDI_SEND_BOOST`); `MasqueSetBidiDownloadReceiveActive` for P2 download leg (poke/wake без send boost); eager activation always schedules send after poke |
| `framer.go` | duplicate `AddActiveStream` re-promotes bidi-boost streams; `controlFrameStreamIDs` prioritizes boost MAX_STREAM_DATA |
| `stream.go` | `Read`/`Write`/`WriteTo` poke+wake when download-active (parity `http3/stream.go`); `WriteTo` auto `MasqueSetBidiDownloadActive` when unset |
| `http3/masque_wake.go` | receive-read wake; `MASQUE_QUIC_BIDI_CONN_WAKE=0` disables conn-level bidi wake |
| `http3/stream.go` | single `MasqueWakeStreamSend` after payload read |
| `http3/client.go` | `ClientConn.MasqueWakeSend()` → `MasqueWakeConnSend`; CONNECT upload chunk env |
| `internal/flowcontrol/masque_threshold.go` | `MASQUE_QUIC_DOWNLOAD_EAGER_WINDOW` (default on): threshold 0 → MAX_STREAM_DATA per read (B7 parity) |

Env: `MASQUE_QUIC_WAKE_SEND_ON_RECEIVE_READ=0` отключает conn-wide `MasqueWakeStreamSend` при bidi bulk localize (CONNECT-stream upload на том же QUIC connection). `MASQUE_QUIC_DOWNLOAD_EAGER_WINDOW=0` restores stock 0.01/0.05 window-update threshold. Client `wakeBidiSendAfterDownloadDelivery` (WriteTo afterDownload) также вызывает `MasquePokeDownloadReceiveWindow` при eager WINDOW (belt-and-suspenders vs field ~15 Mbit/s stall). `MASQUE_QUIC_KEEPALIVE_MS` (default 15s; field/server 5s) и `MASQUE_QUIC_HANDSHAKE_IDLE_MS` (default 5s; field 15s). `MASQUE_CONNECT_STREAM_DIAL_MAX_ATTEMPTS` / `MASQUE_CONNECT_STREAM_DIAL_BACKOFF_MS` — field dial retry (default 3×50ms; remote 5×200ms). `MASQUE_H3_BIDI_DOWNLOAD_DRAIN=0` отключает фоновый discard response DATA при upload-only на одном `*http3.Stream` (parity H2). Prod route CONNECT: `TunnelConnParams.RouteBidiDuplex=true` — upload Write/ReadFrom **не** auto-start drain (concurrent route `WriteTo` owns response reads). Route duplex: `WriteTo` вызывает `stopDownloadDrain` (+ read-deadline poke) до download read; drain polls with short read deadline when idle; `ReadFrom`/`Write` всегда пишут напрямую в `h3` (не `enqueueDuplexUpload` при активном download leg; S33/S34); download-only `WriteTo` держит **64 KiB** buffer (`bidiDownloadInterleaveNeeded`, 16 KiB только при pending enqueue upload). CONNECT-IP ingress ACK wake — отдельно через `h3.FlushConnectIPIngressAckWake`.
