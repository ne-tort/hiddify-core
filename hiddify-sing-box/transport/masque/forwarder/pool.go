package forwarder

import "sync"

var pktPool = sync.Pool{
	New: func() any {
		b := make([]byte, 0, 1600)
		return &b
	},
}

func borrowPacket(n int) []byte {
	bp := pktPool.Get().(*[]byte)
	b := *bp
	if cap(b) < n {
		*bp = b[:0]
		pktPool.Put(bp)
		return make([]byte, n)
	}
	return b[:n]
}

func returnPacket(b []byte) {
	if cap(b) < 64 || cap(b) > 8<<10 {
		return
	}
	b = b[:0]
	pktPool.Put(&b)
}
