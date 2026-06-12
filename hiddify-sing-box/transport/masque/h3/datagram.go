package h3

import (
	"strings"

	"github.com/quic-go/quic-go/http3"
)

// CloudflareLegacyH3DatagramSettingID is the SETTINGS identifier quiche/Cloudflare WARP still
// ship for legacy H3 datagrams (see usque).
const CloudflareLegacyH3DatagramSettingID uint64 = 0x276

const (
	// UDPDatagramWriteSlack is tunnel framing reserved from ConnectIPDatagramCeiling for
	// CONNECT-UDP QUIC HTTP DATAGRAM payloads.
	UDPDatagramWriteSlack = 120
	// UDPWriteMin is the minimum CONNECT-UDP application payload per datagram.
	UDPWriteMin = 512
)

// UDPWriteMax returns masqueUDPWriteMax: ceiling minus slack, clamped to [UDPWriteMin, hardCap].
func UDPWriteMax(effectiveCeiling, hardCap int) int {
	max := effectiveCeiling - UDPDatagramWriteSlack
	if max < UDPWriteMin {
		max = UDPWriteMin
	}
	if hardCap > 0 && max > hardCap {
		max = hardCap
	}
	return max
}

// WarpTransportOptions selects WARP/cf-connect-ip H3 transport extras.
type WarpTransportOptions struct {
	LegacyH3Extras bool
	CfConnectIP    bool
}

// ApplyWarpTransportFields registers legacy H3 datagram SETTINGS and disables compression
// when WARP extras or cf-connect-ip protocol is active.
func ApplyWarpTransportFields(tr *http3.Transport, opts WarpTransportOptions) {
	if tr == nil {
		return
	}
	if !opts.LegacyH3Extras && !opts.CfConnectIP {
		return
	}
	tr.AdditionalSettings = map[uint64]uint64{CloudflareLegacyH3DatagramSettingID: 1}
	tr.DisableCompression = true
}

// CfConnectIPProtocol reports whether WarpConnectIPProtocol selects cf-connect-ip.
func CfConnectIPProtocol(protocol string) bool {
	return strings.EqualFold(strings.TrimSpace(protocol), "cf-connect-ip")
}

// SplitPayloadSizes returns H3 CONNECT-UDP QUIC datagram chunk sizes for one WriteTo.
func SplitPayloadSizes(totalLen, maxPayload int) []int {
	if totalLen <= 0 {
		return []int{0}
	}
	if maxPayload <= 0 || totalLen <= maxPayload {
		return []int{totalLen}
	}
	var sizes []int
	for remaining := totalLen; remaining > 0; {
		n := maxPayload
		if n > remaining {
			n = remaining
		}
		sizes = append(sizes, n)
		remaining -= n
	}
	return sizes
}
