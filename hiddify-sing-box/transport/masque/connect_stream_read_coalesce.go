package masque

import "io"

// masqueConnectStreamReadCoalesceTarget caps how many bytes one net.Conn.Read tries to
// pull from the HTTP/2/3 CONNECT-stream body. quic-go often delivers small DATA chunks;
// coalescing cuts per-chunk overhead in TUN/TCP relay without bufio.Reader's single-fill cap.
const masqueConnectStreamReadCoalesceTarget = 32 * 1024

func coalesceConnectStreamRead(r io.Reader, p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	n, err := r.Read(p)
	if n == 0 {
		return 0, err
	}
	total := n
	goal := len(p)
	if goal > masqueConnectStreamReadCoalesceTarget {
		goal = masqueConnectStreamReadCoalesceTarget
	}
	for total < goal && err == nil {
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
