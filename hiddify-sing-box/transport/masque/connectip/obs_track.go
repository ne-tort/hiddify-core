package connectip

// TrackPacketRx records one accepted inbound CONNECT-IP datagram (raw ReadPacket length).
func TrackPacketRx(n int) {
	if n <= 0 {
		return
	}
	if obs.OnPacketRx != nil {
		obs.OnPacketRx(n)
	}
}

// TrackPacketTx records one successful egress CONNECT-IP datagram (IP payload bytes).
func TrackPacketTx(ipLen int) {
	if ipLen <= 0 {
		return
	}
	if obs.OnPacketTx != nil {
		obs.OnPacketTx(ipLen)
	}
}

// TrackReadExit records a failed CONNECT-IP ReadPacket exit.
func TrackReadExit(err error) {
	if err == nil {
		return
	}
	if obs.OnPacketReadExit != nil {
		obs.OnPacketReadExit(err)
	}
}

// TrackWriteFail records a failed CONNECT-IP WritePacket (ceiling=true for policy reject before send).
func TrackWriteFail(err error, ceiling bool) {
	if err == nil {
		return
	}
	if obs.OnPacketWriteFail != nil {
		obs.OnPacketWriteFail(err, ceiling)
	}
}

// TrackPTBRx records one ICMP PTB datagram returned from WritePacket.
func TrackPTBRx() {
	if obs.OnPacketPTBRx != nil {
		obs.OnPacketPTBRx()
	}
}

// TrackServerWriteIteration mirrors one connectip.Conn.WritePacket hop from the server
// ICMP-relay loop (including PTB follow-up writes).
func TrackServerWriteIteration(payloadLen int, icmpLen int, err error) {
	if err != nil {
		TrackWriteFail(err, false)
		return
	}
	TrackPacketTx(payloadLen)
	if icmpLen > 0 {
		TrackPTBRx()
	}
}
