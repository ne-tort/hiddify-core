package connectip

// UDPWriteHardCap is the max CONNECT-IP/UDP application payload per IPv4 datagram (WAN path).
const UDPWriteHardCap = 1152

// LabUDPWriteHardCap is the self-hosted CONNECT-UDP/CONNECT-IP UDP payload ceiling.
// Must fit in one QUIC HTTP DATAGRAM on typical 1280–1500 paths; larger values caused
// "DATAGRAM frame too large" drops without raising WAN throughput.
const LabUDPWriteHardCap = UDPWriteHardCap

// TCPHTTP3DatagramSlack (WireSlack) is subtracted from the datagram ceiling when sizing the
// prod TCP gVisor link MTU / MaxIPv4WireBytes so proxied IPv4/TCP frames fit the practical H3
// return-path band. Distinct from H3FramingSlack (FramingSlack=80) used for H3NetstackMTU / H2 capsules.
const TCPHTTP3DatagramSlack = 128

// SelfHosted reports whether CONNECT-IP runs without a Warp client certificate (lab/self-hosted).
func SelfHosted(hasWarpClientCert bool) bool {
	return !hasWarpClientCert
}

// UDPWriteHardCapFor returns the CONNECT-IP/UDP application payload ceiling for the deployment mode.
func UDPWriteHardCapFor(selfHosted bool) int {
	if selfHosted {
		return LabUDPWriteHardCap
	}
	return UDPWriteHardCap
}
