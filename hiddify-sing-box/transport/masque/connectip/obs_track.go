package connectip

// TrackPacketRx records one accepted inbound CONNECT-IP datagram (raw ReadPacket length).
func TrackPacketRx(n int) {
	if n <= 0 || !obsEventsEnabled() {
		return
	}
	if obs.OnPacketRx != nil {
		obs.OnPacketRx(n)
	}
}

// TrackPacketTx records one successful egress CONNECT-IP datagram (IP payload bytes).
func TrackPacketTx(ipLen int) {
	if ipLen <= 0 || !obsEventsEnabled() {
		return
	}
	if obs.OnPacketTx != nil {
		obs.OnPacketTx(ipLen)
	}
}

// TrackReadExit records a failed CONNECT-IP ReadPacket exit.
func TrackReadExit(err error) {
	if err == nil || !obsEventsEnabled() {
		return
	}
	if obs.OnPacketReadExit != nil {
		obs.OnPacketReadExit(err)
	}
}

// TrackWriteFail records a failed CONNECT-IP WritePacket (ceiling=true for policy reject before send).
func TrackWriteFail(err error, ceiling bool) {
	if err == nil || !obsEventsEnabled() {
		return
	}
	if obs.OnPacketWriteFail != nil {
		obs.OnPacketWriteFail(err, ceiling)
	}
}

// TrackPTBRx records one ICMP PTB datagram returned from WritePacket.
func TrackPTBRx() {
	if !obsEventsEnabled() {
		return
	}
	if obs.OnPacketPTBRx != nil {
		obs.OnPacketPTBRx()
	}
}
