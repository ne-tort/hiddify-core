# quic-go MASQUE patches (inventory)

При изменении `replace/quic-go-patched/` включать этот diff в описание PR.

| Файл | Назначение |
|------|------------|
| `masque_wake.go` | `MasqueWakeStreamSend`, `MasqueWakeBidiDuplex`, `MasquePokeDownloadReceiveWindow`; eager WINDOW **always on** |
| `internal/flowcontrol/masque_threshold.go` | threshold 0 → MAX_STREAM_DATA per read |
| `http3/masque_wake.go` | wake after Stream.Read / Write on bidi CONNECT |
| `masque_framer.go` | bidi download-active queue front |

## Prod always-on (no env)

- Eager download WINDOW (`MasqueDownloadEagerWindowEnabled` → true)
- Client `wakeBidiSendAfterDownloadDelivery` — 64 KiB batched during WriteTo
- Server hijack relay — batched duplex wake (`UseBatchedDuplexWake`)

## Optional debug env (not prod dataplane switches)

`MASQUE_QUIC_WAKE_SEND_ON_RECEIVE_READ=0`, `MASQUE_QUIC_BIDI_CONN_WAKE=0`, `MASQUE_H3_BIDI_DOWNLOAD_DRAIN=0`, dial retry `MASQUE_CONNECT_STREAM_DIAL_*`.
