package connectip

// UDPWriteHardCap is the max CONNECT-IP/UDP application payload per IPv4 datagram (WAN path).
const UDPWriteHardCap = 1152

// LabUDPWriteHardCap is the self-hosted CONNECT-UDP/CONNECT-IP UDP payload ceiling.
// Must fit in one QUIC HTTP DATAGRAM on typical 1280–1500 paths; larger values caused
// "DATAGRAM frame too large" drops without raising WAN throughput.
const LabUDPWriteHardCap = UDPWriteHardCap

// TCPHTTP3DatagramSlack is subtracted from the datagram ceiling when sizing the gVisor link MTU
// so proxied IPv4/TCP frames fit in one QUIC HTTP DATAGRAM (context id + crypto overhead).
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
