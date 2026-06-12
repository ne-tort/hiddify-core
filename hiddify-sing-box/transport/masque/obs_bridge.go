package masque

import (
	mcip "github.com/sagernet/sing-box/transport/masque/connectip"
)

func init() {
	mcip.RegisterObservabilitySnapshotMerger(mergeConnectIPDatagramOBSMetrics)
}

// ConnectIPObservabilitySnapshot returns the CONNECT_IP_OBS JSON contract map.
func ConnectIPObservabilitySnapshot() map[string]any {
	return mcip.ObservabilitySnapshot()
}

func emitConnectIPObservabilityEvent(reason string) {
	mcip.EmitObservabilityEvent(reason)
}

func incConnectIPSessionReset(reason string) {
	mcip.IncSessionReset(reason)
}

func incConnectIPWriteFailReason(reason string) {
	mcip.IncWriteFailReason(reason)
}

func incConnectIPReadDropReason(reason string) {
	mcip.IncReadDropReason(reason)
}

func incConnectIPEngineDropReason(reason string) {
	mcip.IncEngineDropReason(reason)
}

func setConnectIPSessionID() {
	mcip.SetSessionID()
}

// ObserveConnectIPServerReadError mirrors ClientPacketSession.ReadPacket accounting when
// connectip.Conn.ReadPacket fails on the server packet plane (protocol/masque connectIPNetPacketConn).
func ObserveConnectIPServerReadError(err error) {
	mcip.TrackReadExit(err)
}

// ObserveConnectIPServerReadSuccess records one accepted inbound IP datagram (raw ReadPacket length)
// after parse succeeds on the server CONNECT-IP path.
func ObserveConnectIPServerReadSuccess(rawLen int) {
	mcip.TrackPacketRx(rawLen)
}

// ObserveConnectIPServerWriteIteration mirrors one connectip.Conn.WritePacket hop from the server
// ICMP-relay loop (including PTB follow-up writes).
func ObserveConnectIPServerWriteIteration(payloadLen int, icmpLen int, err error) {
	if err != nil {
		mcip.TrackWriteFail(err, false)
		return
	}
	mcip.TrackPacketTx(payloadLen)
	if icmpLen > 0 {
		mcip.TrackPTBRx()
	}
}

// RegisterConnectIPServerParseDropSupplier merges server-side parse-drop totals into CONNECT_IP_OBS snapshots.
func RegisterConnectIPServerParseDropSupplier(fn func() uint64) {
	mcip.RegisterServerParseDropSupplier(fn)
}
