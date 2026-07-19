package connectip

// ProxiedIPOutboundHeadroom documents the RFC9297 InPlace headroom contract for pool
// slices (quarter-stream varint + context ID slack). Not used in the vendor dataplane;
// must match connectip netstack/pump ProxiedIPDatagramHeadroom and
// http3.ProxiedIPDatagramHeadroom (locked by app TestP215HeadroomEquality).
const ProxiedIPOutboundHeadroom = 16

var outboundPayloadReleaser func([]byte)
var outboundPoolSlice func([]byte) bool

// IPScopeOpener decrypts a CONNECT-IP {opaque} path segment into target prefix + ipproto.
// Injected by the parent (pathbuild); vendor must not import product crypto.
type IPScopeOpener func(opaque string) (target string, ipproto uint8, err error)

var ipScopeOpener IPScopeOpener

// SetIPScopeOpener registers the opaque-path opener used by ParseRequest.
// Pass nil to clear (ParseRequest then rejects non-empty opaque).
func SetIPScopeOpener(fn IPScopeOpener) {
	ipScopeOpener = fn
}

// SetOutboundPayloadReleaseHook registers pool release and a guard for in-place QUIC enqueue.
func SetOutboundPayloadReleaseHook(release func([]byte), isPoolSlice func([]byte) bool) {
	outboundPayloadReleaser = release
	outboundPoolSlice = isPoolSlice
}

// SetOutboundPayloadReleaser is deprecated; use SetOutboundPayloadReleaseHook.
func SetOutboundPayloadReleaser(fn func([]byte)) {
	outboundPayloadReleaser = fn
}
