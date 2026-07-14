package masque

import (
	"encoding/json"
	"log"
	"os"

	h3t "github.com/sagernet/sing-box/transport/masque/h3"
)

// ConnectStreamDataplaneDiag is emitted once per bench CLI start for field A/B proof.
type ConnectStreamDataplaneDiag struct {
	StreamRecvWindowMiB int `json:"stream_recv_window_mib"`
	ConnRecvWindowMiB   int `json:"conn_recv_window_mib"`
	RelayBufKiB         int `json:"relay_buf_kib"`
}

func init() {
	emitConnectStreamDataplaneDiag()
}

func emitConnectStreamDataplaneDiag() {
	if os.Getenv("MASQUE_CONNECT_STREAM_DIAG") == "0" {
		return
	}
	cfg := h3t.TCPConnectStreamQUICConfig(h3t.QUICDialProfile{})
	diag := ConnectStreamDataplaneDiag{
		StreamRecvWindowMiB: int(cfg.InitialStreamReceiveWindow / (1 << 20)),
		ConnRecvWindowMiB:   int(cfg.InitialConnectionReceiveWindow / (1 << 20)),
		RelayBufKiB:         h3t.TunnelWriteToBufLen / 1024,
	}
	b, err := json.Marshal(diag)
	if err != nil {
		return
	}
	log.Printf("masque_connect_stream_diag %s", string(b))
}

// LogConnectStreamBenchStats is a no-op after Invisv rework (coalesce counters removed).
func LogConnectStreamBenchStats() {}
