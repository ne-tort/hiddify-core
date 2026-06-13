package connectip

import (
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	libconnectip "github.com/quic-go/connect-ip-go"
)

type observabilityCounters struct {
	ptbRxTotal                                atomic.Uint64
	packetWriteFailTotal                      atomic.Uint64
	packetReadExitTotal                       atomic.Uint64
	packetTxTotal                             atomic.Uint64
	packetRxTotal                             atomic.Uint64
	bytesTxTotal                              atomic.Uint64
	bytesRxTotal                              atomic.Uint64
	netstackReadInjectTotal                   atomic.Uint64
	netstackReadDropInvalidTotal              atomic.Uint64
	netstackWriteDequeuedTotal                atomic.Uint64
	netstackWriteAttemptTotal                 atomic.Uint64
	netstackWriteSuccessTotal                 atomic.Uint64
	netstackWriteNotifyRetryContinueDropTotal atomic.Uint64
	netstackWriteNotifySlowIterationTotal     atomic.Uint64
	bypassListenPacketTotal                   atomic.Uint64
	openSessionTotal                          atomic.Uint64
	engineIngressTotal                        atomic.Uint64
	engineClassifiedTotal                     atomic.Uint64
	engineDropTotal                           atomic.Uint64
	engineICMPFeedbackTotal                   atomic.Uint64
	enginePMTUUpdateTotal                     atomic.Uint64
	engineEffectiveUDPPayload                 atomic.Uint64
	preTCPIngressDropTotal                    atomic.Uint64
	bridgeUDPTXAttemptTotal                   atomic.Uint64
	bridgeBuildTotal                          atomic.Uint64
	bridgeWriteEnterTotal                     atomic.Uint64
	bridgeWriteChunkTotal                     atomic.Uint64
	bridgeWriteOkTotal                        atomic.Uint64
	bridgeWriteErrTotal                       atomic.Uint64
	firstTxMarkerEmitted                      atomic.Uint32
	firstRxMarkerEmitted                      atomic.Uint32
	emitSeq                                   atomic.Uint64
	sessionSeq                                atomic.Uint64
	lastActiveEmitUnixMilli                   atomic.Int64
	mu                                        sync.Mutex
	sessionResetByReason                      map[string]uint64
	packetWriteFailByReason                   map[string]uint64
	packetReadDropByReason                    map[string]uint64
	engineDropByReason                        map[string]uint64
	enginePMTUUpdateByReason                  map[string]uint64
	bridgeWriteErrByReason                    map[string]uint64
	quicTransportTierByPath                   map[string]uint64
	quicTransportTypeByPath                   map[string]string
	quicTransportBufferTuningOK               uint64
	quicTransportBufferTuningNOK              uint64
	currentSessionID                          string
	currentScopeTarget                        string
	currentScopeIPProto                       uint8
	lastPTBObsEmitUnixMilli                   atomic.Int64
}

var obsCounters = observabilityCounters{
	sessionResetByReason:     make(map[string]uint64),
	packetWriteFailByReason:  make(map[string]uint64),
	packetReadDropByReason:   make(map[string]uint64),
	engineDropByReason:       make(map[string]uint64),
	enginePMTUUpdateByReason: make(map[string]uint64),
	bridgeWriteErrByReason:   make(map[string]uint64),
	quicTransportTierByPath:  make(map[string]uint64),
	quicTransportTypeByPath:  make(map[string]string),
}

var (
	obsSnapshotMerger         func(map[string]any)
	obsServerParseDropSupplier func() uint64
)

// RegisterObservabilitySnapshotMerger merges transport-layer metrics into CONNECT_IP_OBS snapshots.
func RegisterObservabilitySnapshotMerger(fn func(map[string]any)) {
	obsSnapshotMerger = fn
}

// RegisterServerParseDropSupplier merges server-side parse-drop totals into snapshots.
func RegisterServerParseDropSupplier(fn func() uint64) {
	obsServerParseDropSupplier = fn
}

func policyDropICMPReasonSnapshot() map[string]uint64 {
	breakdown := libconnectip.PolicyDropICMPReasonBreakdown()
	for _, reason := range []string{"src_not_allowed", "dst_not_allowed", "proto_not_allowed"} {
		if _, ok := breakdown[reason]; !ok {
			breakdown[reason] = 0
		}
	}
	return breakdown
}

// IncSessionReset records a CONNECT-IP session reset reason.
func IncSessionReset(reason string) {
	if strings.TrimSpace(reason) == "" {
		reason = "unknown"
	}
	obsCounters.mu.Lock()
	obsCounters.sessionResetByReason[reason]++
	obsCounters.mu.Unlock()
	if obsEventsEnabled() {
		EmitObservabilityEvent("session_reset_" + reason)
	}
}

// IncWriteFailReason records a CONNECT-IP packet write failure reason.
func IncWriteFailReason(reason string) {
	if strings.TrimSpace(reason) == "" {
		reason = "unknown"
	}
	obsCounters.mu.Lock()
	obsCounters.packetWriteFailByReason[reason]++
	obsCounters.mu.Unlock()
}

// IncReadDropReason records a CONNECT-IP read/drop reason.
func IncReadDropReason(reason string) {
	if strings.TrimSpace(reason) == "" {
		reason = "unknown"
	}
	obsCounters.mu.Lock()
	obsCounters.packetReadDropByReason[reason]++
	obsCounters.mu.Unlock()
}

// IncPreTCPIngressDropTotal records a pre-TCP netstack ingress cap drop.
func IncPreTCPIngressDropTotal() {
	obsCounters.preTCPIngressDropTotal.Add(1)
}

// IncEngineDropReason records a CONNECT-IP engine drop reason.
func IncEngineDropReason(reason string) {
	if strings.TrimSpace(reason) == "" {
		reason = "unknown"
	}
	obsCounters.engineDropTotal.Add(1)
	obsCounters.mu.Lock()
	obsCounters.engineDropByReason[reason]++
	obsCounters.mu.Unlock()
}

// SetEngineEffectiveUDPPayload records PMTU/effective UDP payload updates.
func SetEngineEffectiveUDPPayload(payload int, reason string) {
	if payload < 0 {
		payload = 0
	}
	obsCounters.engineEffectiveUDPPayload.Store(uint64(payload))
	if strings.TrimSpace(reason) == "" {
		reason = "unknown"
	}
	obsCounters.enginePMTUUpdateTotal.Add(1)
	obsCounters.mu.Lock()
	obsCounters.enginePMTUUpdateByReason[reason]++
	obsCounters.mu.Unlock()
}

// SetSessionID assigns a new CONNECT-IP session id for observability snapshots.
func SetSessionID() {
	seq := obsCounters.sessionSeq.Add(1)
	id := fmt.Sprintf("connect-ip-session-%d-%d", time.Now().UnixNano(), seq)
	obsCounters.mu.Lock()
	obsCounters.currentSessionID = id
	obsCounters.mu.Unlock()
	obsCounters.lastActiveEmitUnixMilli.Store(0)
	obsCounters.firstTxMarkerEmitted.Store(0)
	obsCounters.firstRxMarkerEmitted.Store(0)
	obsCounters.lastPTBObsEmitUnixMilli.Store(0)
}

// SetSessionScope records the active CONNECT-IP scope for snapshots.
func SetSessionScope(target string, ipProto uint8) {
	obsCounters.mu.Lock()
	obsCounters.currentScopeTarget = strings.TrimSpace(target)
	obsCounters.currentScopeIPProto = ipProto
	obsCounters.mu.Unlock()
}

// IncOpenSessionTotal increments successful CONNECT-IP open counter.
func IncOpenSessionTotal() {
	obsCounters.openSessionTotal.Add(1)
}

// RecordQUICTransportPacketConn records QUIC packet conn tier diagnostics.
func RecordQUICTransportPacketConn(path, tier, connType string, bufferTuningOK bool) {
	obsCounters.mu.Lock()
	defer obsCounters.mu.Unlock()
	key := fmt.Sprintf("%s|%s", path, tier)
	obsCounters.quicTransportTierByPath[key]++
	obsCounters.quicTransportTypeByPath[path] = connType
	if bufferTuningOK {
		obsCounters.quicTransportBufferTuningOK++
	} else {
		obsCounters.quicTransportBufferTuningNOK++
	}
}

const activeObsSampleMask = uint64(127)

func maybeEmitActiveSnapshot(planeTick uint64) {
	if !obsEventsEnabled() {
		return
	}
	last := obsCounters.lastActiveEmitUnixMilli.Load()
	if last != 0 {
		if (planeTick & activeObsSampleMask) != 0 {
			return
		}
		now := time.Now().UnixMilli()
		if now-last < 1000 {
			return
		}
		if !obsCounters.lastActiveEmitUnixMilli.CompareAndSwap(last, now) {
			return
		}
		EmitObservabilityEvent("periodic_active")
		return
	}
	now := time.Now().UnixMilli()
	if !obsCounters.lastActiveEmitUnixMilli.CompareAndSwap(0, now) {
		return
	}
	EmitObservabilityEvent("periodic_active")
}

func maybeEmitPTBObs(reason string) {
	if !obsEventsEnabled() {
		return
	}
	now := time.Now().UnixMilli()
	last := obsCounters.lastPTBObsEmitUnixMilli.Load()
	if last != 0 && now-last < 1000 {
		return
	}
	if !obsCounters.lastPTBObsEmitUnixMilli.CompareAndSwap(last, now) {
		return
	}
	EmitObservabilityEvent(reason)
}

// ObservabilitySnapshot returns the CONNECT_IP_OBS JSON contract map.
func ObservabilitySnapshot() map[string]any {
	obsCounters.mu.Lock()
	reasons := make(map[string]uint64, len(obsCounters.sessionResetByReason))
	for k, v := range obsCounters.sessionResetByReason {
		reasons[k] = v
	}
	writeReasons := make(map[string]uint64, len(obsCounters.packetWriteFailByReason))
	for k, v := range obsCounters.packetWriteFailByReason {
		writeReasons[k] = v
	}
	readReasons := make(map[string]uint64, len(obsCounters.packetReadDropByReason))
	for k, v := range obsCounters.packetReadDropByReason {
		readReasons[k] = v
	}
	engineDropReasons := make(map[string]uint64, len(obsCounters.engineDropByReason))
	for k, v := range obsCounters.engineDropByReason {
		engineDropReasons[k] = v
	}
	pmtuUpdateReasons := make(map[string]uint64, len(obsCounters.enginePMTUUpdateByReason))
	for k, v := range obsCounters.enginePMTUUpdateByReason {
		pmtuUpdateReasons[k] = v
	}
	bridgeWriteErrReasons := make(map[string]uint64, len(obsCounters.bridgeWriteErrByReason))
	for k, v := range obsCounters.bridgeWriteErrByReason {
		bridgeWriteErrReasons[k] = v
	}
	quicConnTier := make(map[string]uint64, len(obsCounters.quicTransportTierByPath))
	for k, v := range obsCounters.quicTransportTierByPath {
		quicConnTier[k] = v
	}
	quicConnType := make(map[string]string, len(obsCounters.quicTransportTypeByPath))
	for k, v := range obsCounters.quicTransportTypeByPath {
		quicConnType[k] = v
	}
	bufferTuningOK := obsCounters.quicTransportBufferTuningOK
	bufferTuningNOK := obsCounters.quicTransportBufferTuningNOK
	sessionID := obsCounters.currentSessionID
	scopeTarget := obsCounters.currentScopeTarget
	scopeIPProto := obsCounters.currentScopeIPProto
	obsCounters.mu.Unlock()
	out := map[string]any{
		"connect_ip_obs_contract_version":                            "v1",
		"connect_ip_session_id":                                      sessionID,
		"connect_ip_scope_target":                                    scopeTarget,
		"connect_ip_scope_ipproto":                                   scopeIPProto,
		"connect_ip_emit_seq":                                        obsCounters.emitSeq.Load(),
		"connect_ip_ptb_rx_total":                                    obsCounters.ptbRxTotal.Load(),
		"connect_ip_packet_write_fail_total":                         obsCounters.packetWriteFailTotal.Load(),
		"connect_ip_packet_write_fail_reason_total":                  writeReasons,
		"connect_ip_packet_read_exit_total":                          obsCounters.packetReadExitTotal.Load(),
		"connect_ip_packet_read_drop_reason_total":                   readReasons,
		"connect_ip_packet_tx_total":                                 obsCounters.packetTxTotal.Load(),
		"connect_ip_packet_rx_total":                                 obsCounters.packetRxTotal.Load(),
		"connect_ip_bytes_tx_total":                                  obsCounters.bytesTxTotal.Load(),
		"connect_ip_bytes_rx_total":                                  obsCounters.bytesRxTotal.Load(),
		"connect_ip_netstack_read_inject_total":                      obsCounters.netstackReadInjectTotal.Load(),
		"connect_ip_netstack_read_drop_invalid_total":                obsCounters.netstackReadDropInvalidTotal.Load(),
		"connect_ip_netstack_write_dequeued_total":                   obsCounters.netstackWriteDequeuedTotal.Load(),
		"connect_ip_netstack_write_attempt_total":                    obsCounters.netstackWriteAttemptTotal.Load(),
		"connect_ip_netstack_write_success_total":                    obsCounters.netstackWriteSuccessTotal.Load(),
		"connect_ip_netstack_write_notify_retry_continue_drop_total": obsCounters.netstackWriteNotifyRetryContinueDropTotal.Load(),
		"connect_ip_netstack_write_notify_slow_iteration_total":      obsCounters.netstackWriteNotifySlowIterationTotal.Load(),
		"connect_ip_bypass_listenpacket_total":                       obsCounters.bypassListenPacketTotal.Load(),
		"connect_ip_open_session_total":                              obsCounters.openSessionTotal.Load(),
		"connect_ip_engine_ingress_total":                            obsCounters.engineIngressTotal.Load(),
		"connect_ip_engine_classified_total":                         obsCounters.engineClassifiedTotal.Load(),
		"connect_ip_engine_drop_total":                               obsCounters.engineDropTotal.Load(),
		"connect_ip_engine_drop_reason_total":                        engineDropReasons,
		"connect_ip_engine_icmp_feedback_total":                      obsCounters.engineICMPFeedbackTotal.Load(),
		"connect_ip_engine_pmtu_update_total":                        obsCounters.enginePMTUUpdateTotal.Load(),
		"connect_ip_engine_pmtu_update_reason_total":                 pmtuUpdateReasons,
		"connect_ip_engine_effective_udp_payload":                    obsCounters.engineEffectiveUDPPayload.Load(),
		"connect_ip_pre_tcp_ingress_drop_total":                      obsCounters.preTCPIngressDropTotal.Load(),
		"connect_ip_bridge_udp_tx_attempt_total":                     obsCounters.bridgeUDPTXAttemptTotal.Load(),
		"connect_ip_bridge_build_total":                              obsCounters.bridgeBuildTotal.Load(),
		"connect_ip_bridge_write_enter_total":                        obsCounters.bridgeWriteEnterTotal.Load(),
		"connect_ip_bridge_write_chunk_total":                        obsCounters.bridgeWriteChunkTotal.Load(),
		"connect_ip_bridge_write_ok_total":                           obsCounters.bridgeWriteOkTotal.Load(),
		"connect_ip_bridge_write_err_total":                          obsCounters.bridgeWriteErrTotal.Load(),
		"connect_ip_bridge_write_err_reason_total":                   bridgeWriteErrReasons,
		"quic_transport_packet_conn_tier":                            quicConnTier,
		"quic_transport_packet_conn_type":                            quicConnType,
		"quic_transport_buffer_tuning_ok":                            bufferTuningOK,
		"quic_transport_buffer_tuning_not_ok":                        bufferTuningNOK,
		"connect_ip_session_reset_total":                             reasons,
		"connect_ip_capsule_unknown_total":                           libconnectip.UnknownCapsuleTotal(),
		"connect_ip_datagram_context_unknown_total":                  libconnectip.UnknownContextDatagramTotal(),
		"connect_ip_datagram_malformed_total":                        libconnectip.MalformedDatagramTotal(),
		"connect_ip_stream_capsule_datagram_ingress_drop_total":      libconnectip.StreamCapsuleDatagramIngressDropTotal(),
		"connect_ip_policy_drop_icmp_total":                          libconnectip.PolicyDropICMPTotal(),
		"connect_ip_policy_drop_icmp_attempt_total":                  libconnectip.PolicyDropICMPAttemptTotal(),
		"connect_ip_policy_drop_icmp_reason_total":                   policyDropICMPReasonSnapshot(),
	}
	if obsSnapshotMerger != nil {
		obsSnapshotMerger(out)
	}
	if fn := obsServerParseDropSupplier; fn != nil {
		out["connect_ip_server_parse_drop_total"] = fn()
	}
	return out
}

// EmitObservabilityEvent logs a CONNECT_IP_OBS JSON snapshot when enabled.
func EmitObservabilityEvent(reason string) {
	if !obsEventsEnabled() {
		return
	}
	snapshot := ObservabilitySnapshot()
	snapshot["connect_ip_emit_seq"] = obsCounters.emitSeq.Add(1)
	snapshot["event_reason"] = reason
	encoded, err := json.Marshal(snapshot)
	if err != nil {
		log.Printf("CONNECT_IP_OBS marshal_error=%v", err)
		return
	}
	log.Printf("CONNECT_IP_OBS %s", encoded)
}
