// Package losslocus aggregates CONNECT-IP drop/loss counters by named locus
// (TUN / client_ingress / client_egress / underlay_h3 / server_s2) for field scrape.
//
// Enabled with MASQUE_CONNECT_IP_RELAY_STATS=1 → RESULT_CONNECT_IP_LOSS_LOCUS
// and /tmp/masque-connect-ip-loss-locus.json (~2 Hz).
package losslocus

import (
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	connectipgo "github.com/quic-go/connect-ip-go"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/sagernet/sing-box/transport/masque/connectip/relaystats"
)

func init() {
	v := strings.TrimSpace(os.Getenv("MASQUE_CONNECT_IP_RELAY_STATS"))
	if v == "1" || strings.EqualFold(v, "true") || strings.EqualFold(v, "yes") {
		Enable()
	}
}

// TUN / host-kernel path (client L3).
var (
	tunWriteFail    atomic.Uint64
	tunWriteShort   atomic.Uint64
	tunNoConsumer   atomic.Uint64
	tunInjectClosed atomic.Uint64
	tunInjectInvalid atomic.Uint64
)

// Server S2 teardown discards (packet returned without WritePacket).
var serverS2DiscardTeardown atomic.Uint64

var (
	active atomic.Bool
	once   atomic.Bool
)

// Enable starts LOSS_LOCUS emission (also via env in init).
func Enable() {
	active.Store(true)
	if once.CompareAndSwap(false, true) {
		go ticker()
	}
}

func enabled() bool { return active.Load() }

// RecordTunWriteFail: deliverIngress tunWrite error.
func RecordTunWriteFail() {
	tunWriteFail.Add(1)
}

// RecordTunWriteShort: tunWrite returned n != len.
func RecordTunWriteShort() {
	tunWriteShort.Add(1)
}

// RecordTunNoConsumer: neither tunWrite nor stackInject wired (packet vanished).
func RecordTunNoConsumer() {
	tunNoConsumer.Add(1)
}

// RecordTunInjectClosed: gVisor inject skipped because stack closed/terminal.
func RecordTunInjectClosed() {
	tunInjectClosed.Add(1)
}

// RecordTunInjectInvalid: non-IPv4/IPv6 frame dropped at inject.
func RecordTunInjectInvalid() {
	tunInjectInvalid.Add(1)
}

// RecordServerS2DiscardTeardown: downloadCh/writeCh discard on stopped plane.
func RecordServerS2DiscardTeardown() {
	serverS2DiscardTeardown.Add(1)
}

// Reset clears process-local TUN/S2 discard counters (tests). Does not reset wire/quic globals.
func Reset() {
	tunWriteFail.Store(0)
	tunWriteShort.Store(0)
	tunNoConsumer.Store(0)
	tunInjectClosed.Store(0)
	tunInjectInvalid.Store(0)
	serverS2DiscardTeardown.Store(0)
}

// Snapshot is the scrape contract: every key is a named locus counter.
type Snapshot struct {
	Role   string            `json:"role"`
	Drops  map[string]uint64 `json:"drops"`
	Total  uint64            `json:"total_drops"`
	TsUnix int64             `json:"ts_unix_ms"`
}

// SnapshotNow builds the current locus map. role is a scrape tag (client|server|local).
func SnapshotNow(role string) Snapshot {
	if role == "" {
		role = "local"
	}
	drops := map[string]uint64{
		// TUN / L3 inject (client)
		"tun_write_fail":     tunWriteFail.Load(),
		"tun_write_short":    tunWriteShort.Load(),
		"tun_no_consumer":    tunNoConsumer.Load(),
		"tun_inject_closed":  tunInjectClosed.Load(),
		"tun_inject_invalid": tunInjectInvalid.Load(),

		// Client wire ingress (connect-ip-go)
		"client_ingress_capsule_full":  connectipgo.StreamCapsuleDatagramIngressDropTotal(),
		"client_ingress_malformed":     connectipgo.MalformedDatagramTotal(),
		"client_ingress_unknown_ctx":   connectipgo.UnknownContextDatagramTotal(),
		"client_ingress_validation":    connectipgo.ValidationDropTotal(),

		// Client wire egress
		"client_egress_compose_drop": connectipgo.OutgoingComposeDropTotal(),
		"client_egress_write_fail":   connectipgo.SnapshotCIPClientRelayStats().WriteFail,

		// Underlay H3 (quic-go / http3) — H2 has no DATAGRAM rcv queue
		"underlay_h3_quic_rcv_queue":       quic.DatagramReceiveQueueDropTotal(),
		"underlay_h3_stream_dgram_queue":   http3.StreamDatagramQueueDropTotal(),
		"underlay_h3_stream_recv_closed":   http3.StreamDatagramRecvClosedDropTotal(),
		"underlay_h3_unknown_stream":       http3.UnknownStreamDatagramDropTotal(),
		"underlay_h3_packer_oversize":      quic.DatagramPackerOversizeDropTotal(),

		// Server S2
		"server_s2_write_fail":        relaystats.SnapshotNow().S2CWriteFail,
		"server_s2_discard_teardown":  serverS2DiscardTeardown.Load(),
		"server_s2_rto_retransmit":    relaystats.SnapshotNow().S2CRTORetransmit,
	}

	// Optional engine drops from OBS (client ingress classification).
	if eng := engineDropTotal(); eng > 0 {
		drops["client_ingress_engine"] = eng
	}
	if pre := preTCPIngressDropTotal(); pre > 0 {
		drops["client_ingress_pre_tcp_cap"] = pre
	}

	var total uint64
	for k, v := range drops {
		// RTO retransmit is repair, not a silent drop — exclude from total_drops.
		if k == "server_s2_rto_retransmit" {
			continue
		}
		total += v
	}
	return Snapshot{Role: role, Drops: drops, Total: total, TsUnix: time.Now().UnixMilli()}
}

func ticker() {
	t := time.NewTicker(500 * time.Millisecond)
	defer t.Stop()
	for range t.C {
		if !enabled() {
			continue
		}
		role := strings.TrimSpace(os.Getenv("MASQUE_CONNECT_IP_LOSS_ROLE"))
		if role == "" {
			role = "local"
		}
		Log(role)
		writeFile(role)
	}
}

// Log emits RESULT_CONNECT_IP_LOSS_LOCUS (one line, machine-parseable).
func Log(role string) {
	if !enabled() {
		return
	}
	s := SnapshotNow(role)
	raw, err := json.Marshal(s.Drops)
	if err != nil {
		return
	}
	log.Printf("RESULT_CONNECT_IP_LOSS_LOCUS role=%s total_drops=%d drops=%s", s.Role, s.Total, string(raw))
}

func writeFile(role string) {
	s := SnapshotNow(role)
	raw, err := json.Marshal(s)
	if err != nil {
		return
	}
	_ = os.WriteFile(filepath.Join(os.TempDir(), "masque-connect-ip-loss-locus.json"), raw, 0o644)
}

// EngineDropSupplier optionally provides OBS engine drop total (set from connectip to avoid import cycle).
var EngineDropSupplier func() uint64
var PreTCPIngressDropSupplier func() uint64

func engineDropTotal() uint64 {
	if EngineDropSupplier != nil {
		return EngineDropSupplier()
	}
	return 0
}

func preTCPIngressDropTotal() uint64 {
	if PreTCPIngressDropSupplier != nil {
		return PreTCPIngressDropSupplier()
	}
	return 0
}
