package frame

import "io"

// ParseHTTPDatagramUDP interprets CONNECT-UDP HTTP Datagram payload (RFC 9297 / MASQUE).
// Return convention matches masque-go parseProxiedDatagramPayload for H3 parity:
// truncated / empty structural cases use io.EOF; callers drop (do not treat as capsule mis-framing).
func ParseHTTPDatagramUDP(data []byte) (payload []byte, ok bool, err error) {
	if len(data) == 0 {
		return nil, false, io.EOF
	}
	if data[0] == 0 {
		return data[1:], true, nil
	}
	if data[0]&0xc0 == 0 {
		return nil, false, nil
	}
	if data[0]&0x3f != 0 {
		return nil, false, nil
	}
	switch data[0] >> 6 {
	case 1:
		if len(data) < 2 {
			return nil, false, io.EOF
		}
		if data[1] == 0 {
			return data[2:], true, nil
		}
		return nil, false, nil
	case 2:
		if len(data) < 4 {
			return nil, false, io.EOF
		}
		if data[1] == 0 && data[2] == 0 && data[3] == 0 {
			return data[4:], true, nil
		}
		return nil, false, nil
	case 3:
		if len(data) < 8 {
			return nil, false, io.EOF
		}
		if data[1] == 0 && data[2] == 0 && data[3] == 0 && data[4] == 0 && data[5] == 0 && data[6] == 0 && data[7] == 0 {
			return data[8:], true, nil
		}
		return nil, false, nil
	}
	return nil, false, io.EOF
}
