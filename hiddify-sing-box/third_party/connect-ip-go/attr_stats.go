package connectip

import (
	"encoding/json"
	"log"
	"os"
	"strings"
	"sync"
	"time"
)

var connectIPIngressAttrOnce sync.Once

func connectIPIngressAttrEnabled() bool {
	// Same gate as H2 S2C attr so one lab env enables both ends.
	v := os.Getenv("MASQUE_CONNECT_IP_H2_ATTR")
	return v == "1" || strings.EqualFold(v, "true") || strings.EqualFold(v, "yes")
}

func connectIPIngressAttrFile() string {
	if p := strings.TrimSpace(os.Getenv("MASQUE_CONNECT_IP_INGRESS_ATTR_FILE")); p != "" {
		return p
	}
	return "/tmp/masque-connect-ip-ingress-stats.json"
}

type connectIPIngressStatsSnapshot struct {
	StreamCapsuleDatagramIngressDrop uint64 `json:"stream_capsule_datagram_ingress_drop"`
	UnknownContextDatagram           uint64 `json:"unknown_context_datagram"`
	MalformedDatagram                uint64 `json:"malformed_datagram"`
	ValidationDrop                   uint64 `json:"validation_drop"`
}

func snapshotConnectIPIngressStats() connectIPIngressStatsSnapshot {
	return connectIPIngressStatsSnapshot{
		StreamCapsuleDatagramIngressDrop: StreamCapsuleDatagramIngressDropTotal(),
		UnknownContextDatagram:           UnknownContextDatagramTotal(),
		MalformedDatagram:                MalformedDatagramTotal(),
		ValidationDrop:                   ValidationDropTotal(),
	}
}

// ensureConnectIPIngressAttrEmitter logs RESULT_CONNECT_IP_INGRESS_STATS ~2 Hz when
// MASQUE_CONNECT_IP_H2_ATTR=1 (client-side soft-limit / window drop attribution).
func ensureConnectIPIngressAttrEmitter() {
	if !connectIPIngressAttrEnabled() {
		return
	}
	connectIPIngressAttrOnce.Do(func() {
		go func() {
			t := time.NewTicker(2 * time.Second)
			defer t.Stop()
			var lastLog time.Time
			for range t.C {
				snap := snapshotConnectIPIngressStats()
				b, err := json.Marshal(snap)
				if err != nil {
					continue
				}
				_ = os.WriteFile(connectIPIngressAttrFile(), b, 0o644)
				if time.Since(lastLog) >= 5*time.Second {
					log.Printf("RESULT_CONNECT_IP_INGRESS_STATS %s", b)
					lastLog = time.Now()
				}
			}
		}()
	})
}
