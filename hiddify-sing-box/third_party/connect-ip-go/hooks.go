package connectip

// ProxiedIPOutboundHeadroom must match connectip.ProxiedIPDatagramHeadroom (netstack pool layout).
const ProxiedIPOutboundHeadroom = 16

var outboundPayloadReleaser func([]byte)
var outboundPoolSlice func([]byte) bool

// SetOutboundPayloadReleaseHook registers pool release and a guard for in-place QUIC enqueue.
func SetOutboundPayloadReleaseHook(release func([]byte), isPoolSlice func([]byte) bool) {
	outboundPayloadReleaser = release
	outboundPoolSlice = isPoolSlice
}

// SetOutboundPayloadReleaser is deprecated; use SetOutboundPayloadReleaseHook.
func SetOutboundPayloadReleaser(fn func([]byte)) {
	outboundPayloadReleaser = fn
}
