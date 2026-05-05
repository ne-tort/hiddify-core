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

const (
	flowVarTarget  = "target"
	flowVarIPProto = "ipproto"
)

// Request is the parsed CONNECT-IP request returned from ParseRequest.
// Empty fields mean unscoped flow forwarding (full proxy scope).
type Request struct {
	Target   netip.Prefix
	HasTarget bool
	IPProto  uint8
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
	if r.Proto != requestProtocol {
		return nil, &RequestParseError{
			HTTPStatus: http.StatusNotImplemented,
			Err:        fmt.Errorf("unexpected protocol: %s", r.Proto),
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
	for _, variable := range template.Varnames() {
		switch variable {
		case flowVarTarget, flowVarIPProto:
		default:
			return ErrFlowForwardingUnsupported
		}
	}
	return nil
}

func matchTemplateRequestValues(r *http.Request, template *uritemplate.Template) *uritemplate.Values {
	candidates := []string{
		strings.TrimSpace(r.URL.String()),
		strings.TrimSpace(r.URL.Path),
		strings.TrimSpace(r.RequestURI),
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
