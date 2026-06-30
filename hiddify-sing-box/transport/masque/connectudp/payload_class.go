package connectudp

import (
	cip "github.com/sagernet/sing-box/transport/masque/connectip"
	h2c "github.com/sagernet/sing-box/transport/masque/h2"
)

// SteadyUploadPayloadLenH2 is max RFC9297 DATAGRAM capsule payload (bulk upload localize target, UDP-5p1).
func SteadyUploadPayloadLenH2() int {
	return h2c.MaxUDPPayloadPerDatagramCapsule()
}

// SteadyUploadPayloadLenH3 is practical H3 proxied UDP bulk size (connect-ip wire ceiling band).
func SteadyUploadPayloadLenH3() int {
	return cip.MaxIPv4Datagram(cip.DefaultDatagramCeilingMax)
}
