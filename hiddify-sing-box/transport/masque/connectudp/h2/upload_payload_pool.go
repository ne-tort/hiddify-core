package h2

import "sync"

var uploadPayloadPool = sync.Pool{
	New: func() any {
		b := make([]byte, 0, 1200)
		return &b
	},
}

func borrowUploadPayload(n int) []byte {
	bp := uploadPayloadPool.Get().(*[]byte)
	b := *bp
	if cap(b) < n {
		return make([]byte, n)
	}
	return b[:n]
}

func releaseUploadPayload(b []byte) {
	if b == nil || cap(b) == 0 {
		return
	}
	b = b[:0]
	uploadPayloadPool.Put(&b)
}
