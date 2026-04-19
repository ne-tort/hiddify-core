package l3router

import "encoding/binary"

func packetSrcDstV4(b []byte) (src, dst uint32, ok bool) {
	if len(b) < 20 || (b[0]>>4) != 4 {
		return 0, 0, false
	}
	return binary.BigEndian.Uint32(b[12:16]), binary.BigEndian.Uint32(b[16:20]), true
}

func packetDstV4(b []byte) (dst uint32, ok bool) {
	if len(b) < 20 || (b[0]>>4) != 4 {
		return 0, false
	}
	return binary.BigEndian.Uint32(b[16:20]), true
}

func packetSrcDstV6HiLo(b []byte) (srcHi, srcLo, dstHi, dstLo uint64, ok bool) {
	if len(b) < 40 || (b[0]>>4) != 6 {
		return 0, 0, 0, 0, false
	}
	return binary.BigEndian.Uint64(b[8:16]), binary.BigEndian.Uint64(b[16:24]), binary.BigEndian.Uint64(b[24:32]), binary.BigEndian.Uint64(b[32:40]), true
}

func packetDstV6HiLo(b []byte) (dstHi, dstLo uint64, ok bool) {
	if len(b) < 40 || (b[0]>>4) != 6 {
		return 0, 0, false
	}
	return binary.BigEndian.Uint64(b[24:32]), binary.BigEndian.Uint64(b[32:40]), true
}
