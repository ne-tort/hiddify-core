package connectip

import cipgo "github.com/quic-go/connect-ip-go"

func init() {
	cipgo.SetOutboundPayloadReleaseHook(releaseOutboundPayload, IsOutboundPoolSlice)
}
