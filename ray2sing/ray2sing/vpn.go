package ray2sing

import (
	"bytes"
	"compress/zlib"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"io"
	"strings"

	T "github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
)

const maxAmneziaVpnInflated = 4 << 20 // 4 MiB

// DecodeAmneziaVpnINIs expands an Amnezia `vpn://` share (or .vpn file body) into
// one or more WireGuard/AmneziaWG INI texts ([Interface]/[Peer]).
//
// Format (amnezia-client ExportController / LxBox §110):
//
//	vpn:// + base64url(qCompress(JSON))
//	vpn:// + base64url(JSON)   // uncompressed fallback
//
// qCompress = 4-byte big-endian uncompressed length + zlib stream.
// JSON containers[].awg|wireguard.last_config.config holds the INI.
func DecodeAmneziaVpnINIs(raw string) ([]string, error) {
	t := strings.TrimSpace(raw)
	if !strings.HasPrefix(strings.ToLower(t), "vpn://") {
		return nil, E.New("vpn: not a vpn:// link")
	}
	payload := t[len("vpn://"):]
	if i := strings.IndexByte(payload, '#'); i >= 0 {
		payload = payload[:i]
	}
	payload = strings.TrimSpace(payload)
	if payload == "" {
		return nil, E.New("vpn: empty payload")
	}

	rawBytes, err := decodeBase64URLFlexible(payload)
	if err != nil {
		return nil, E.Cause(err, "vpn: invalid base64")
	}
	jsonText, err := inflateAmneziaVpn(rawBytes)
	if err != nil {
		return nil, err
	}

	var root map[string]any
	if err := json.Unmarshal([]byte(jsonText), &root); err != nil {
		return nil, E.Cause(err, "vpn: payload is not valid JSON")
	}
	containers, _ := root["containers"].([]any)
	if len(containers) == 0 {
		return nil, E.New("vpn: no containers[]")
	}

	dns1, _ := root["dns1"].(string)
	dns2, _ := root["dns2"].(string)

	var inis []string
	for _, c := range containers {
		cm, ok := c.(map[string]any)
		if !ok {
			continue
		}
		for _, proto := range []string{"awg", "wireguard"} {
			ini := extractAmneziaIni(cm[proto])
			if ini == "" {
				continue
			}
			ini = substituteAmneziaDNS(ini, dns1, dns2)
			inis = append(inis, ini)
		}
	}
	if len(inis) == 0 {
		return nil, E.New("vpn: no WireGuard/AmneziaWG containers")
	}
	return inis, nil
}

// AmneziaVpnEndpoint parses vpn:// into the first WG/AWG endpoint.
// Multi-container links are expanded earlier in expandDecodedConfig.
func AmneziaVpnEndpoint(rawURL string) (*T.Endpoint, error) {
	inis, err := DecodeAmneziaVpnINIs(rawURL)
	if err != nil {
		return nil, err
	}
	return AWGSingboxTxt(inis[0])
}

func decodeBase64URLFlexible(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	s = strings.ReplaceAll(s, "\n", "")
	s = strings.ReplaceAll(s, "\r", "")
	if m := len(s) % 4; m != 0 {
		s += strings.Repeat("=", 4-m)
	}
	if b, err := base64.URLEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	if b, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "=")); err == nil {
		return b, nil
	}
	if b, err := base64.StdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return base64.RawStdEncoding.DecodeString(strings.TrimRight(s, "="))
}

func inflateAmneziaVpn(b []byte) (string, error) {
	if len(b) > 4 {
		claimed := binary.BigEndian.Uint32(b[:4])
		if claimed > 0 && claimed <= maxAmneziaVpnInflated {
			r, err := zlib.NewReader(bytes.NewReader(b[4:]))
			if err == nil {
				defer r.Close()
				out, err := io.ReadAll(io.LimitReader(r, int64(claimed)+1))
				if err == nil && uint32(len(out)) == claimed {
					return string(out), nil
				}
				// claimed mismatch / partial — try full zlib read
				r2, err2 := zlib.NewReader(bytes.NewReader(b[4:]))
				if err2 == nil {
					defer r2.Close()
					out2, err2 := io.ReadAll(io.LimitReader(r2, maxAmneziaVpnInflated))
					if err2 == nil && len(out2) > 0 && (out2[0] == '{' || out2[0] == '[') {
						return string(out2), nil
					}
				}
			}
		}
	}
	// Uncompressed JSON fallback (importController parity).
	s := strings.TrimSpace(string(b))
	if strings.HasPrefix(s, "{") {
		return s, nil
	}
	return "", E.New("vpn: payload is neither qCompress nor JSON")
}

func extractAmneziaIni(protoObj any) string {
	m, ok := protoObj.(map[string]any)
	if !ok {
		return ""
	}
	last := m["last_config"]
	switch v := last.(type) {
	case string:
		var obj map[string]any
		if err := json.Unmarshal([]byte(v), &obj); err != nil {
			return ""
		}
		last = obj
	case map[string]any:
		// ok
	default:
		return ""
	}
	lm, ok := last.(map[string]any)
	if !ok {
		return ""
	}
	ini, _ := lm["config"].(string)
	if !strings.Contains(ini, "[Interface]") || !strings.Contains(ini, "[Peer]") {
		return ""
	}
	return ini
}

func substituteAmneziaDNS(ini, dns1, dns2 string) string {
	out := ini
	if dns1 != "" {
		out = strings.ReplaceAll(out, "$PRIMARY_DNS", dns1)
	}
	if dns2 != "" {
		out = strings.ReplaceAll(out, "$SECONDARY_DNS", dns2)
	}
	return out
}
