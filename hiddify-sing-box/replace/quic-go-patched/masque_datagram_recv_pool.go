package quic

import "sync"

const masqueDatagramRecvBufCap = 2048

var masqueDatagramRecvPool sync.Pool

func init() {
	masqueDatagramRecvPool.New = func() any {
		b := make([]byte, masqueDatagramRecvBufCap)
		return &b
	}
}

func acquireMasqueDatagramRecvBuf(n int) []byte {
	if n <= 0 {
		return nil
	}
	bp, ok := masqueDatagramRecvPool.Get().(*[]byte)
	if !ok || bp == nil {
		b := make([]byte, n)
		return b
	}
	b := *bp
	if cap(b) < n {
		return make([]byte, n)
	}
	return b[:n]
}

// ReleaseMasqueDatagramReceiveBuffer returns a CONNECT-UDP/CONNECT-IP DATAGRAM receive
// buffer to the pool after the consumer copies payload (fountain S2C hot path).
func ReleaseMasqueDatagramReceiveBuffer(b []byte) {
	if len(b) == 0 {
		return
	}
	c := cap(b)
	if c < 256 || c > 64*1024 {
		return
	}
	buf := b[:c]
	masqueDatagramRecvPool.Put(&buf)
}

// AcquireMasqueDatagramRecvBuf returns a pooled receive buffer with length n.
func AcquireMasqueDatagramRecvBuf(n int) []byte {
	return acquireMasqueDatagramRecvBuf(n)
}
