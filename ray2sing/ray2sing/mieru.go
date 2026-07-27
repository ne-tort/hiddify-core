package ray2sing

import (
	"net/url"
	"strconv"
	"strings"

	T "github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
)

// MieruSingbox maps a single mieru:// (hiddify-style) share link to one outbound.
// Official opaque mieru://<base64-protobuf> is rejected — use mierus://.
func MieruSingbox(rawURL string) (*T.Outbound, error) {
	outs, err := MieruSingboxAll(rawURL)
	if err != nil {
		return nil, err
	}
	if len(outs) == 0 {
		return nil, E.New("mieru: no outbound produced")
	}
	return outs[0], nil
}

// MieruSingboxAll expands share links into N outbounds (one per port/protocol pair).
//
// Official enfein formats (docs/client-install.md § Sharing):
//   mierus://user:pass@host?port=&protocol=…  — simple (canonical for Clash/mihomo/Hiddify)
//   mieru://<base64-protobuf>                 — full ClientConfig; not a single outbound → reject
//
// Also accepted for compatibility:
//   mieru://user:pass@host?port=&protocol=…   — same simple grammar on mieru:// scheme
//   mieru://host:port/?transport=…            — legacy Hiddify single-outbound style
func MieruSingboxAll(rawURL string) ([]*T.Outbound, error) {
	scheme, rest, ok := strings.Cut(rawURL, "://")
	if !ok {
		return nil, E.New("mieru: invalid URL")
	}
	scheme = strings.ToLower(scheme)

	switch scheme {
	case "mierus":
		return parseMierusSimple(rawURL)
	case "mieru":
		if isOpaqueMieruProtobuf(rest) {
			return nil, E.New("mieru: official mieru:// protobuf share link (full client config) is not supported as a single outbound; use mierus:// or mieru://user:pass@host?port=&protocol=")
		}
		// Official simple grammar sometimes appears on mieru:// — treat as mierus://.
		if isMieruSimpleStyle(rest) {
			return parseMierusSimple("mierus://" + rest)
		}
		return parseMieruHiddifyStyle(rawURL)
	default:
		return nil, E.New("mieru: unsupported scheme ", scheme)
	}
}

// isMieruSimpleStyle detects enfein simple links that use the mieru:// scheme by mistake
// or for compatibility: userinfo + repeated port= query (same as mierus://).
func isMieruSimpleStyle(rest string) bool {
	rest = strings.TrimSpace(rest)
	if !strings.Contains(rest, "@") {
		return false
	}
	q := rest
	if i := strings.IndexByte(rest, '?'); i >= 0 {
		q = rest[i+1:]
	} else {
		return false
	}
	if i := strings.IndexByte(q, '#'); i >= 0 {
		q = q[:i]
	}
	for _, part := range strings.Split(q, "&") {
		key, _, _ := strings.Cut(part, "=")
		if strings.EqualFold(strings.TrimSpace(key), "port") {
			return true
		}
	}
	return false
}

func isOpaqueMieruProtobuf(rest string) bool {
	rest = strings.TrimSpace(rest)
	if rest == "" {
		return false
	}
	// Fragment-only / query-only with authority is not opaque protobuf.
	if strings.Contains(rest, "@") {
		return false
	}
	// host:port/?… looks like hiddify-style without userinfo
	if strings.Contains(rest, "/") || strings.Contains(rest, "?") {
		hostPart := rest
		if i := strings.IndexAny(rest, "/?"); i >= 0 {
			hostPart = rest[:i]
		}
		if strings.Contains(hostPart, ".") || strings.Contains(hostPart, ":") || netLooksLikeHost(hostPart) {
			return false
		}
	}
	// Bare base64 body (possibly with #fragment)
	body := rest
	if i := strings.IndexByte(rest, '#'); i >= 0 {
		body = rest[:i]
	}
	body = strings.TrimSpace(body)
	return len(body) > 16 && !strings.Contains(body, ":") && isBase64CharsOnly(body)
}

func netLooksLikeHost(s string) bool {
	s = strings.Trim(s, "[]")
	return s != "" && (strings.Contains(s, ".") || strings.Count(s, ":") > 0 || isIPv4ish(s))
}

func isIPv4ish(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return false
	}
	for _, p := range parts {
		if _, err := strconv.Atoi(p); err != nil {
			return false
		}
	}
	return true
}

func parseMierusSimple(rawURL string) ([]*T.Outbound, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}
	q := u.Query()
	ports := q["port"]
	protocols := q["protocol"]
	if len(ports) == 0 {
		return nil, E.New("mierus: at least one port= query parameter is required")
	}
	if len(protocols) == 0 {
		// default all to TCP
		protocols = make([]string, len(ports))
		for i := range protocols {
			protocols[i] = "TCP"
		}
	}
	if len(ports) != len(protocols) {
		return nil, E.New("mierus: port and protocol query counts must match")
	}

	user := ""
	pass := ""
	if u.User != nil {
		user = u.User.Username()
		pass, _ = u.User.Password()
	}
	host := u.Hostname()
	if host == "" {
		return nil, E.New("mierus: host required")
	}
	name := u.Fragment
	multiplexing := firstNonEmpty(q.Get("multiplexing"), q.Get("multiplex"))
	handshake := firstNonEmpty(q.Get("handshake-mode"), q.Get("handshake_mode"), q.Get("handshakeMode"))
	traffic := firstNonEmpty(q.Get("traffic-pattern"), q.Get("traffic_pattern"), q.Get("trafficPattern"))
	mtu := toUInt16(q.Get("mtu"), 0)

	out := make([]*T.Outbound, 0, len(ports))
	for i, portStr := range ports {
		portStr = strings.TrimSpace(portStr)
		proto := strings.ToUpper(strings.TrimSpace(protocols[i]))
		if proto == "" {
			proto = "TCP"
		}
		opts := &T.MieruOutboundOptions{
			ServerOptions: T.ServerOptions{
				Server: host,
			},
			Transport:      proto,
			UserName:       user,
			Password:       pass,
			Multiplexing:   multiplexing,
			HandshakeMode:  handshake,
			TrafficPattern: traffic,
		}
		if mtu > 0 {
			opts.MTU = mtu
		}
		if strings.Contains(portStr, "-") {
			opts.ServerPortRanges = []string{portStr}
		} else {
			p := toUInt16(portStr, 0)
			if p == 0 {
				return nil, E.New("mierus: invalid port ", portStr)
			}
			opts.ServerPort = p
		}
		tag := name
		if tag == "" {
			tag = "mieru"
		}
		if len(ports) > 1 {
			tag = tag + "-" + proto + "-" + portStr
		}
		out = append(out, &T.Outbound{
			Tag:     tag,
			Type:    "mieru",
			Options: opts,
		})
	}
	return out, nil
}

func parseMieruHiddifyStyle(rawURL string) ([]*T.Outbound, error) {
	u, err := ParseUrl(rawURL, 0)
	if err != nil {
		return nil, err
	}
	decoded := u.Params
	transport := strings.ToUpper(getOneOfN(decoded, "TCP", "transport", "protocol"))
	// If protocol was joined "TCP,UDP" from multi-value, reject — use mierus://
	if strings.Contains(transport, ",") {
		return nil, E.New("mieru: multiple protocols require mierus:// with repeated port=&protocol=")
	}
	opts := &T.MieruOutboundOptions{
		DialerOptions:  getDialerOptions(decoded),
		ServerOptions:  u.GetServerOption(),
		Transport:      transport,
		UserName:       firstNonEmpty(u.Username, decoded["username"], decoded["user"]),
		Password:       firstNonEmpty(u.Password, decoded["password"], decoded["pass"]),
		Multiplexing:   getOneOfN(decoded, "", "multiplexing", "multiplex"),
		HandshakeMode:  getOneOfN(decoded, "", "handshake mode", "handshakemode", "handshake-mode"),
		TrafficPattern: getOneOfN(decoded, "", "traffic pattern", "trafficpattern", "traffic-pattern"),
	}
	if mtu := toUInt16(decoded["mtu"], 0); mtu > 0 {
		opts.MTU = mtu
	}
	if ports := firstNonEmpty(decoded["server ports"], decoded["serverports"], decoded["ports"]); ports != "" {
		for _, p := range strings.Split(ports, ",") {
			p = strings.TrimSpace(p)
			if p == "" {
				continue
			}
			opts.ServerPortRanges = append(opts.ServerPortRanges, p)
		}
	}
	if opts.ServerPort == 0 && len(opts.ServerPortRanges) == 0 {
		return nil, E.New("mieru: server port required")
	}
	tag := u.Name
	if tag == "" {
		tag = "mieru"
	}
	return []*T.Outbound{{
		Tag:     tag,
		Type:    "mieru",
		Options: opts,
	}}, nil
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}
