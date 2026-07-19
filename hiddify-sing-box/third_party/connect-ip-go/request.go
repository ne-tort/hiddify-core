package connectip

import (
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"reflect"
	"strconv"
	"strings"

	"github.com/dunglas/httpsfv"
	"github.com/quic-go/quic-go/http3"
	"github.com/yosida95/uritemplate/v3"
)

const requestProtocol = "connect-ip"

// extendedConnectProtocol returns the RFC 8441 Extended CONNECT tunnel protocol (:protocol pseudo-header).
// net/http HTTP/2 server sets Req.Proto to "HTTP/2.0"; the tunnel protocol is Header[":protocol"].
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

var capsuleProtocolHeaderValue string
var ErrFlowForwardingUnsupported = errors.New("connect-ip: flow forwarding template variables (target/ipproto) are not supported")
var ErrInvalidFlowForwardingTarget = errors.New("connect-ip: invalid flow forwarding target")
var ErrInvalidFlowForwardingIPProto = errors.New("connect-ip: invalid flow forwarding ipproto")

func init() {
	v, err := httpsfv.Marshal(httpsfv.NewItem(true))
	if err != nil {
		panic(fmt.Sprintf("failed to marshal capsule protocol header value: %v", err))
	}
	capsuleProtocolHeaderValue = v
}

// requireCapsuleProtocolTrue validates Capsule-Protocol as Structured Fields Boolean true (?1).
// Used for CONNECT-IP request parse (RFC 9484 §4.4 / 9297) and client response check (§4.5).
func requireCapsuleProtocolTrue(values []string) error {
	if len(values) == 0 {
		return fmt.Errorf("missing Capsule-Protocol header")
	}
	item, err := httpsfv.UnmarshalItem(values)
	if err != nil {
		return fmt.Errorf("invalid capsule header value: %s", values)
	}
	v, ok := item.Value.(bool)
	if !ok {
		return fmt.Errorf("incorrect capsule header value type: %s", reflect.TypeOf(item.Value))
	}
	if !v {
		return fmt.Errorf("incorrect capsule header value: %t", item.Value)
	}
	return nil
}

// validateResponseCapsuleProtocol enforces RFC 9484 §4.5: after 2xx, Capsule Protocol
// response requirements must hold — product requires Capsule-Protocol: ?1.
func validateResponseCapsuleProtocol(h http.Header) error {
	if h == nil {
		return fmt.Errorf("connect-ip: missing Capsule-Protocol in response")
	}
	values, ok := h[http3.CapsuleProtocolHeader]
	if !ok {
		// Canonical / MIME header map may store under different casing via Get.
		if v := h.Get(http3.CapsuleProtocolHeader); v != "" {
			values = []string{v}
		} else {
			return fmt.Errorf("connect-ip: missing Capsule-Protocol in response")
		}
	}
	if err := requireCapsuleProtocolTrue(values); err != nil {
		return fmt.Errorf("connect-ip: invalid Capsule-Protocol in response: %w", err)
	}
	return nil
}

const (
	flowVarTarget  = "target"
	flowVarIPProto = "ipproto"
	flowVarOpaque  = "opaque"
)

// Request is the parsed CONNECT-IP request returned from ParseRequest.
// Empty fields mean unscoped flow forwarding (full proxy scope).
type Request struct {
	Target     netip.Prefix
	HasTarget  bool
	IPProto    uint8
	HasIPProto bool
}

// RequestParseError is returned from ParseRequest if parsing the CONNECT-UDP request fails.
// It is recommended that the request is rejected with the corresponding HTTP status code.
type RequestParseError struct {
	HTTPStatus int
	Err        error
}

func (e *RequestParseError) Error() string { return e.Err.Error() }
func (e *RequestParseError) Unwrap() error { return e.Err }

// ParseRequest parses a CONNECT-IP request.
// The template is the URI template that clients will use to configure this proxy.
func ParseRequest(r *http.Request, template *uritemplate.Template) (*Request, error) {
	if err := validateFlowForwardingTemplateVars(template); err != nil {
		return nil, &RequestParseError{
			HTTPStatus: http.StatusNotImplemented,
			Err:        err,
		}
	}

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
	capsuleHeaderValues, ok := r.Header[http3.CapsuleProtocolHeader]
	if !ok {
		return nil, &RequestParseError{
			HTTPStatus: http.StatusBadRequest,
			Err:        fmt.Errorf("missing Capsule-Protocol header"),
		}
	}
	if err := requireCapsuleProtocolTrue(capsuleHeaderValues); err != nil {
		return nil, &RequestParseError{
			HTTPStatus: http.StatusBadRequest,
			Err:        err,
		}
	}

	request := &Request{}
	if len(template.Varnames()) == 0 {
		return request, nil
	}
	values := matchTemplateRequestValues(r, template)
	if values == nil {
		return nil, &RequestParseError{
			HTTPStatus: http.StatusBadRequest,
			Err:        fmt.Errorf("connect-ip: request does not match flow forwarding template"),
		}
	}
	opaqueValue := strings.TrimSpace(values.Get(flowVarOpaque).String())
	if opaqueValue != "" {
		if ipScopeOpener == nil {
			return nil, &RequestParseError{
				HTTPStatus: http.StatusBadRequest,
				Err:        errors.New("connect-ip: opaque path requires IPScopeOpener"),
			}
		}
		targetStr, ipproto, openErr := ipScopeOpener(opaqueValue)
		if openErr != nil {
			return nil, &RequestParseError{
				HTTPStatus: http.StatusBadRequest,
				Err:        fmt.Errorf("connect-ip: opaque path: %w", openErr),
			}
		}
		target, err := netip.ParsePrefix(targetStr)
		if err != nil {
			return nil, &RequestParseError{
				HTTPStatus: http.StatusBadRequest,
				Err:        fmt.Errorf("%w: %s", ErrInvalidFlowForwardingTarget, targetStr),
			}
		}
		request.Target = target
		request.HasTarget = true
		request.IPProto = ipproto
		request.HasIPProto = true
		return request, nil
	}
	targetValue := strings.TrimSpace(values.Get(flowVarTarget).String())
	if targetValue != "" {
		target, err := netip.ParsePrefix(targetValue)
		if err != nil {
			return nil, &RequestParseError{
				HTTPStatus: http.StatusBadRequest,
				Err:        fmt.Errorf("%w: %s", ErrInvalidFlowForwardingTarget, targetValue),
			}
		}
		request.Target = target
		request.HasTarget = true
	}
	ipprotoValue := strings.TrimSpace(values.Get(flowVarIPProto).String())
	if ipprotoValue != "" {
		v, err := strconv.ParseUint(ipprotoValue, 10, 8)
		if err != nil {
			return nil, &RequestParseError{
				HTTPStatus: http.StatusBadRequest,
				Err:        fmt.Errorf("%w: %s", ErrInvalidFlowForwardingIPProto, ipprotoValue),
			}
		}
		request.IPProto = uint8(v)
		request.HasIPProto = true
	}
	return request, nil
}

func validateFlowForwardingTemplateVars(template *uritemplate.Template) error {
	if template == nil {
		return errors.New("connect-ip: URI template is nil")
	}
	for _, variable := range template.Varnames() {
		switch variable {
		case flowVarTarget, flowVarIPProto, flowVarOpaque:
		default:
			return ErrFlowForwardingUnsupported
		}
	}
	return nil
}

func matchTemplateRequestValues(r *http.Request, template *uritemplate.Template) *uritemplate.Values {
	requestURIWithAuthority := ""
	if host := strings.TrimSpace(r.Host); host != "" {
		switch requestURI := strings.TrimSpace(r.RequestURI); {
		case requestURI == "":
		case strings.HasPrefix(requestURI, "https://"), strings.HasPrefix(requestURI, "http://"):
			requestURIWithAuthority = requestURI
		default:
			if !strings.HasPrefix(requestURI, "/") {
				requestURI = "/" + requestURI
			}
			requestURIWithAuthority = "https://" + host + requestURI
		}
	}

	candidates := []string{
		strings.TrimSpace(r.URL.String()),
		strings.TrimSpace(r.URL.Path),
		strings.TrimSpace(r.RequestURI),
		requestURIWithAuthority,
	}
	for _, candidate := range candidates {
		if candidate == "" {
			continue
		}
		values := template.Match(candidate)
		matched := false
		for _, variable := range template.Varnames() {
			if strings.TrimSpace(values.Get(variable).String()) != "" {
				matched = true
				break
			}
		}
		if matched {
			return &values
		}
	}
	return nil
}
