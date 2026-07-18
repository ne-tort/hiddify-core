package frame

import (
	"fmt"
	"net/http"
	"net/url"
	"reflect"
	"strconv"
	"strings"

	"github.com/dunglas/httpsfv"
	"github.com/quic-go/quic-go/http3"
	"github.com/sagernet/sing-box/transport/masque/pathbuild"
	"github.com/yosida95/uritemplate/v3"
)

const (
	// RequestProtocol is the Extended CONNECT :protocol / Proto token for CONNECT-UDP.
	RequestProtocol = "connect-udp"

	uriTemplateTargetHost = "target_host"
	uriTemplateTargetPort = "target_port"
	uriTemplateOpaque     = "opaque"
)

// CapsuleProtocolHeaderValue is the serialized Capsule-Protocol: ?1 header value.
var CapsuleProtocolHeaderValue string

func init() {
	v, err := httpsfv.Marshal(httpsfv.NewItem(true))
	if err != nil {
		panic(fmt.Sprintf("failed to marshal capsule protocol header value: %v", err))
	}
	CapsuleProtocolHeaderValue = v
}

// Request is the parsed CONNECT-UDP request returned from ParseRequest.
type Request struct {
	Target string
	Host   string
}

// RequestParseError is returned from ParseRequest if parsing the CONNECT-UDP request fails.
type RequestParseError struct {
	HTTPStatus int
	Err        error
}

func (e *RequestParseError) Error() string { return e.Err.Error() }
func (e *RequestParseError) Unwrap() error { return e.Err }

func extendedConnectProtocol(r *http.Request) string {
	if r == nil {
		return ""
	}
	if v := strings.TrimSpace(r.Header.Get(":protocol")); v != "" {
		return v
	}
	p := strings.TrimSpace(r.Proto)
	if p == "" {
		return ""
	}
	if len(p) >= 5 && strings.EqualFold(p[:5], "http/") {
		return ""
	}
	return p
}

func connectUDPTemplateMatchCandidates(r *http.Request, tmpl *url.URL) []string {
	if r == nil || tmpl == nil {
		return nil
	}
	var out []string
	appendNonEmpty := func(s string) {
		s = strings.TrimSpace(s)
		if s != "" {
			out = append(out, s)
		}
	}

	appendNonEmpty(r.URL.String())
	if path := strings.TrimSpace(r.URL.Path); path != "" {
		if q := strings.TrimSpace(r.URL.RawQuery); q != "" {
			appendNonEmpty(path + "?" + q)
		} else {
			appendNonEmpty(path)
		}
	}
	appendNonEmpty(r.RequestURI)

	requestURIWithAuthority := ""
	if auth := strings.TrimSpace(r.Host); auth != "" {
		switch requestURI := strings.TrimSpace(r.RequestURI); {
		case requestURI == "":
		case strings.HasPrefix(strings.ToLower(requestURI), "http://"),
			strings.HasPrefix(strings.ToLower(requestURI), "https://"):
			requestURIWithAuthority = requestURI
		default:
			if !strings.HasPrefix(requestURI, "/") {
				requestURI = "/" + requestURI
			}
			scheme := strings.TrimSpace(tmpl.Scheme)
			if scheme == "" {
				scheme = "https"
			}
			requestURIWithAuthority = scheme + "://" + auth + requestURI
		}
	}
	appendNonEmpty(requestURIWithAuthority)
	return out
}

// ParseRequest parses a CONNECT-UDP request against the configured URI template.
func ParseRequest(r *http.Request, template *uritemplate.Template) (*Request, error) {
	u, err := url.Parse(template.Raw())
	if err != nil {
		return nil, &RequestParseError{
			HTTPStatus: http.StatusInternalServerError,
			Err:        fmt.Errorf("failed to parse template: %w", err),
		}
	}

	if r.Method != http.MethodConnect {
		return nil, &RequestParseError{
			HTTPStatus: http.StatusMethodNotAllowed,
			Err:        fmt.Errorf("expected CONNECT request, got %s", r.Method),
		}
	}
	proto := extendedConnectProtocol(r)
	if !strings.EqualFold(proto, RequestProtocol) {
		return nil, &RequestParseError{
			HTTPStatus: http.StatusNotImplemented,
			Err:        fmt.Errorf("unexpected protocol: %q", proto),
		}
	}
	capsuleHeaderValues, ok := r.Header[http3.CapsuleProtocolHeader]
	if !ok {
		// RFC 9297 §3.4: Capsule-Protocol is SHOULD send, not MUST. H2 without the header → 400
		// (stricter product). H3: some stacks set r.Proto=connect-udp but do not surface the
		// header in r.Header — accept (D-R4 stack quirk); do not harden reject until surfacing.
		if !strings.EqualFold(strings.TrimSpace(r.Proto), RequestProtocol) {
			return nil, &RequestParseError{
				HTTPStatus: http.StatusBadRequest,
				Err:        fmt.Errorf("missing %s header", http3.CapsuleProtocolHeader),
			}
		}
	} else {
		item, err := httpsfv.UnmarshalItem(capsuleHeaderValues)
		if err != nil {
			return nil, &RequestParseError{
				HTTPStatus: http.StatusBadRequest,
				Err:        fmt.Errorf("invalid capsule header value: %s", capsuleHeaderValues),
			}
		}
		if v, ok := item.Value.(bool); !ok {
			return nil, &RequestParseError{
				HTTPStatus: http.StatusBadRequest,
				Err:        fmt.Errorf("incorrect capsule header value type: %s", reflect.TypeOf(item.Value)),
			}
		} else if !v {
			return nil, &RequestParseError{
				HTTPStatus: http.StatusBadRequest,
				Err:        fmt.Errorf("incorrect capsule header value: %t", item.Value),
			}
		}
	}
	if r.Host != u.Host {
		return nil, &RequestParseError{
			HTTPStatus: http.StatusBadRequest,
			Err:        fmt.Errorf("host in :authority (%s) does not match template host (%s)", r.Host, u.Host),
		}
	}

	var targetHost string
	var targetPortStr string
	var opaque string
	candidates := connectUDPTemplateMatchCandidates(r, u)
	for _, candidate := range candidates {
		if candidate == "" {
			continue
		}
		match := template.Match(candidate)
		targetHost = strings.TrimSpace(match.Get(uriTemplateTargetHost).String())
		targetPortStr = strings.TrimSpace(match.Get(uriTemplateTargetPort).String())
		opaque = strings.TrimSpace(match.Get(uriTemplateOpaque).String())
		if opaque != "" || (targetHost != "" && targetPortStr != "") {
			break
		}
	}
	if opaque != "" {
		if !pathbuild.TemplateHasOpaque(template) {
			return nil, &RequestParseError{
				HTTPStatus: http.StatusBadRequest,
				Err:        fmt.Errorf("opaque path segment requires path_obfuscation"),
			}
		}
		h, p, openErr := pathbuild.OpenHostPort(pathbuild.ActiveKey(true), opaque)
		if openErr != nil {
			return nil, &RequestParseError{
				HTTPStatus: http.StatusBadRequest,
				Err:        fmt.Errorf("opaque path: %w", openErr),
			}
		}
		targetHost = h
		targetPortStr = strconv.Itoa(int(p))
	}
	if targetHost == "" || targetPortStr == "" {
		return nil, &RequestParseError{
			HTTPStatus: http.StatusBadRequest,
			Err:        fmt.Errorf("expected target_host and target_port (or opaque)"),
		}
	}
	targetHost = unescape(targetHost)
	if strings.Contains(targetHost, ":") {
		targetHost = "[" + targetHost + "]"
	}
	targetPort, err := strconv.Atoi(targetPortStr)
	if err != nil {
		return nil, &RequestParseError{
			HTTPStatus: http.StatusBadRequest,
			Err:        fmt.Errorf("failed to decode target_port: %w", err),
		}
	}
	// RFC 9298 §3: target_port MUST be an integer between 1 and 65535.
	if targetPort < 1 || targetPort > 65535 {
		return nil, &RequestParseError{
			HTTPStatus: http.StatusBadRequest,
			Err:        fmt.Errorf("target_port out of range: %d", targetPort),
		}
	}
	return &Request{
		Target: fmt.Sprintf("%s:%d", targetHost, targetPort),
		Host:   r.Host,
	}, nil
}

func unescape(s string) string { return strings.ReplaceAll(s, "%3A", ":") }
