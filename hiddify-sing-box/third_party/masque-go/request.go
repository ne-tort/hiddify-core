package masque

import (
	"fmt"
	"net/http"
	"net/url"
	"reflect"
	"strconv"
	"strings"

	"github.com/dunglas/httpsfv"
	"github.com/quic-go/quic-go/http3"
	"github.com/yosida95/uritemplate/v3"
)

const requestProtocol = "connect-udp"

// extendedConnectProtocol returns the RFC 8441 Extended CONNECT protocol name (:protocol pseudo-header).
// net/http on HTTP/2 sets req.Proto to the wire HTTP version ("HTTP/2.0"); the tunnel protocol appears
// in Header[":protocol"]. HTTP/3 clients often set Req.Proto alone (without :protocol header).
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

// connectUDPTemplateMatchCandidates builds URIs for uritemplate matching.
// Extended CONNECT over HTTP/2 may expose path+query via RequestURI with an empty/absent parsed URL,
// or Path without RawQuery split in separate fields; mirroring TCP parsing in endpoint_server.
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

	// Parity with connect-ip-go matchTemplateRequestValues / protocol/masque parseTCPTargetFromRequest:
	// path-only or scheme-less RequestURI may omit a leading slash; still match absolute templates.
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

var capsuleProtocolHeaderValue string

func init() {
	v, err := httpsfv.Marshal(httpsfv.NewItem(true))
	if err != nil {
		panic(fmt.Sprintf("failed to marshal capsule protocol header value: %v", err))
	}
	capsuleProtocolHeaderValue = v
}

// Request is the parsed CONNECT-UDP request returned from ParseRequest.
// Target is the target server that the client requests to connect to.
// It can either be DNS name:port or an IP:port.
type Request struct {
	Target string
	Host   string
}

// RequestParseError is returned from ParseRequest if parsing the CONNECT-UDP request fails.
// It is recommended that the request is rejected with the corresponding HTTP status code.
type RequestParseError struct {
	HTTPStatus int
	Err        error
}

func (e *RequestParseError) Error() string { return e.Err.Error() }
func (e *RequestParseError) Unwrap() error { return e.Err }

// ParseRequest parses a CONNECT-UDP request.
// The template is the URI template that clients will use to configure this UDP proxy.
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
	if !strings.EqualFold(proto, requestProtocol) {
		return nil, &RequestParseError{
			HTTPStatus: http.StatusNotImplemented,
			Err:        fmt.Errorf("unexpected protocol: %q", proto),
		}
	}
	if r.Host != u.Host {
		return nil, &RequestParseError{
			HTTPStatus: http.StatusBadRequest,
			Err:        fmt.Errorf("host in :authority (%s) does not match template host (%s)", r.Host, u.Host),
		}
	}
	// The capsule protocol header is optional, but if it's present,
	// we need to validate its value.
	capsuleHeaderValues, ok := r.Header[http3.CapsuleProtocolHeader]
	if ok {
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

	var targetHost string
	var targetPortStr string
	candidates := connectUDPTemplateMatchCandidates(r, u)
	for _, candidate := range candidates {
		if candidate == "" {
			continue
		}
		match := template.Match(candidate)
		targetHost = strings.TrimSpace(match.Get(uriTemplateTargetHost).String())
		targetPortStr = strings.TrimSpace(match.Get(uriTemplateTargetPort).String())
		if targetHost != "" && targetPortStr != "" {
			break
		}
	}
	if targetHost == "" || targetPortStr == "" {
		return nil, &RequestParseError{
			HTTPStatus: http.StatusBadRequest,
			Err:        fmt.Errorf("expected target_host and target_port"),
		}
	}
	targetHost = unescape(targetHost)
	// IPv6 addresses need to be enclosed in [], otherwise resolving the address will fail.
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
	return &Request{
		Target: fmt.Sprintf("%s:%d", targetHost, targetPort),
		Host:   r.Host,
	}, nil
}

func escape(s string) string   { return strings.ReplaceAll(s, ":", "%3A") }
func unescape(s string) string { return strings.ReplaceAll(s, "%3A", ":") }
