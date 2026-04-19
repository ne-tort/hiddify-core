package l3routerendpoint

func makeIPv4(src [4]byte, dst [4]byte) []byte {
	pkt := make([]byte, 20)
	pkt[0] = 0x45
	copy(pkt[12:16], src[:])
	copy(pkt[16:20], dst[:])
	return pkt
}
