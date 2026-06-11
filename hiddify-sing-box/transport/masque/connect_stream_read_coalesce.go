package masque

import "io"

// masqueConnectStreamReadCoalesceTarget caps how many bytes one net.Conn.Read (or one
// streamConn.WriteTo iteration) tries to pull from the HTTP/2/3 CONNECT-stream body.
// quic-go often delivers small DATA chunks; coalescing cuts per-chunk overhead in TUN/TCP relay.
// 8 MiB aligns with protocol/masque relayCopyBuffered and http3 bodyCopyBufferSize — fewer DATA
// / syscall iterations on saturated download paths versus 4 MiB (same bench, upload≫download).
const masqueConnectStreamReadCoalesceTarget = 8 * 1024 * 1024

// masqueConnectStreamReadCoalescePerCall caps one coalesceConnectStreamRead / WriteTo
// iteration (avoids blocking until full masqueConnectStreamReadCoalesceTarget). Sized for
// steady pipelining once upload-side pipe flushes are prompt (see h3MasqueBufferedPipeWriter).
const masqueConnectStreamReadCoalescePerCall = 1024 * 1024

// masqueConnectStreamReadCoalesceContinueMin: only attempt follow-up inner Reads after the
// first chunk when the first read already returned at least this many bytes. Otherwise a
// second Read can block forever waiting to fill the caller's buffer (e.g. 4-byte "pong"
// into reply[8]) — net.Conn expects not to stall after delivering available payload.
// 512 keeps control-sized tails safe while coalescing common ~0.5–1 KiB first QUIC/H3 DATA
// slices into fewer TUN writes than 1024 (download asymmetry on bench).
const masqueConnectStreamReadCoalesceContinueMin = 512

// masqueConnectStreamReadCoalesceBulkMinLen: streamConn.WriteTo / ReadBuffer scratch (≥32 KiB).
// Follow-up Reads with continueMin=1 belong only on that path — on smaller caller buffers a
// blocking second Read after ~256 B of iperf banner stalls upload (bench: iperf3 interrupt).
const masqueConnectStreamReadCoalesceBulkMinLen = 32 * 1024

// connectStreamReadBuffered reports whether r may return more bytes without blocking on I/O.
type connectStreamReadBuffered interface {
	ConnectStreamReadBuffered() bool
}

func connectStreamReaderHasBuffered(r io.Reader) bool {
	for r != nil {
		switch x := r.(type) {
		case connectStreamReadBuffered:
			return x.ConnectStreamReadBuffered()
		case *h3MasqueResponseReadCloser:
			r = x.inner
			continue
		case *h2ConnectStreamResponseBody:
			return x.connectStreamReadBuffered()
		case *connectStreamDownloadFeeder:
			return x.ConnectStreamReadBuffered()
		default:
			return false
		}
	}
	return false
}

// coalesceConnectStreamReadFeeder is used only by connectStreamDownloadFeeder (background drain).
// Follow-up Reads run only while ConnectStreamReadBuffered — a blocking read for the next in-flight
// DATA frame on the same HTTP/3 CONNECT stream stalls duplex upload (bench iperf3 interrupt).
func coalesceConnectStreamReadFeeder(r io.Reader, p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	n, err := r.Read(p)
	if n == 0 {
		return 0, err
	}
	total := n
	if err != nil {
		if total > 0 && err == io.EOF {
			return total, nil
		}
		return total, err
	}
	goal := len(p)
	if goal > masqueConnectStreamReadCoalescePerCall {
		goal = masqueConnectStreamReadCoalescePerCall
	}
	if goal > masqueConnectStreamReadCoalesceTarget {
		goal = masqueConnectStreamReadCoalesceTarget
	}
	for total < goal && err == nil {
		if !connectStreamReaderHasBuffered(r) {
			break
		}
		nn, err2 := r.Read(p[total:])
		err = err2
		if nn <= 0 {
			break
		}
		total += nn
	}
	if total > 0 && err == io.EOF {
		return total, nil
	}
	return total, err
}

func coalesceConnectStreamRead(r io.Reader, p []byte) (int, error) {
	return coalesceConnectStreamReadWithPerCallCap(r, p, masqueConnectStreamReadCoalescePerCall)
}

func coalesceConnectStreamReadWithPerCallCap(r io.Reader, p []byte, perCallCap int) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	n, err := r.Read(p)
	if n == 0 {
		return 0, err
	}
	total := n
	if err != nil {
		if total > 0 && err == io.EOF {
			return total, nil
		}
		return total, err
	}
	continueMin := masqueConnectStreamReadCoalesceContinueMin
	if len(p) >= masqueConnectStreamReadCoalesceBulkMinLen {
		// iperf banners / control tails on the response stream are often <512 B; a blocking
		// follow-up Read here stalls HTTP/3 upload on the same QUIC stream (0 B bench upload).
		if total < masqueConnectStreamReadCoalesceContinueMin {
			return total, nil
		}
		continueMin = 1
	} else if total >= masqueConnectStreamReadCoalesceContinueMin {
		continueMin = 1
	}
	if total < continueMin {
		return total, nil
	}
	goal := len(p)
	if perCallCap > 0 && goal > perCallCap {
		goal = perCallCap
	}
	if goal > masqueConnectStreamReadCoalescePerCall {
		goal = masqueConnectStreamReadCoalescePerCall
	}
	if goal > masqueConnectStreamReadCoalesceTarget {
		goal = masqueConnectStreamReadCoalesceTarget
	}
	for total < goal && err == nil {
		if !connectStreamReaderHasBuffered(r) {
			break
		}
		nn, err2 := r.Read(p[total:])
		err = err2
		if nn <= 0 {
			break
		}
		total += nn
	}
	if total > 0 && err == io.EOF {
		return total, nil
	}
	return total, err
}
