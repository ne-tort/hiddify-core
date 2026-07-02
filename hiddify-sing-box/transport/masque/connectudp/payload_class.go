package connectudp

import (
	h2c "github.com/sagernet/sing-box/transport/masque/h2"
)

// steadyUploadH3WireBytes is connectip.MaxIPv4WireBytes (1372); duplicated here for W-UDP-4 path isolation.
const steadyUploadH3WireBytes = 1372

// SteadyUploadPayloadLenH2 is max RFC9297 DATAGRAM capsule payload (bulk upload localize target, UDP-5p1).
func SteadyUploadPayloadLenH2() int {
	return h2c.MaxUDPPayloadPerDatagramCapsule()
}

// SteadyUploadPayloadLenH3 is practical H3 proxied UDP bulk size (MASQUE H3 wire ceiling band).
func SteadyUploadPayloadLenH3() int {
	return steadyUploadH3WireBytes
}
