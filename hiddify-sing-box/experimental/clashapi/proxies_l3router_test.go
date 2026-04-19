package clashapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	l3routerendpoint "github.com/sagernet/sing-box/protocol/l3router"

	"github.com/go-chi/chi/v5"
)

type testEndpointManager struct {
	endpoints []adapter.Endpoint
}

func (m *testEndpointManager) Start(stage adapter.StartStage) error { return nil }
func (m *testEndpointManager) Close() error                         { return nil }
func (m *testEndpointManager) Endpoints() []adapter.Endpoint        { return m.endpoints }
func (m *testEndpointManager) Get(tag string) (adapter.Endpoint, bool) {
	for _, ep := range m.endpoints {
		if ep.Tag() == tag {
			return ep, true
		}
	}
	return nil, false
}
func (m *testEndpointManager) Remove(tag string) error {
	return nil
}
func (m *testEndpointManager) Create(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, endpointType string, options any) error {
	return nil
}

type testOutboundManager struct {
	outbounds map[string]adapter.Outbound
}

func (m *testOutboundManager) Start(stage adapter.StartStage) error { return nil }
func (m *testOutboundManager) Close() error                         { return nil }
func (m *testOutboundManager) Outbound(tag string) (adapter.Outbound, bool) {
	o, ok := m.outbounds[tag]
	return o, ok
}
func (m *testOutboundManager) Outbounds() []adapter.Outbound { return nil }
func (m *testOutboundManager) Default() adapter.Outbound     { return nil }
func (m *testOutboundManager) Remove(tag string) error       { return nil }
func (m *testOutboundManager) Create(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, outboundType string, options any) error {
	return nil
}

func newTestL3Endpoint(tag string) *l3routerendpoint.Endpoint {
	loggerFactory := log.NewNOPFactory()
	ep, err := l3routerendpoint.NewEndpoint(context.Background(), nil, loggerFactory.Logger(), tag, option.L3RouterEndpointOptions{})
	if err != nil {
		panic(err)
	}
	return ep.(*l3routerendpoint.Endpoint)
}

func TestL3RouterControlAPIPayloadValidationAndUpsert(t *testing.T) {
	ep := newTestL3Endpoint("l3-test")

	server := &Server{
		outbound: &testOutboundManager{outbounds: map[string]adapter.Outbound{}},
		endpoint: &testEndpointManager{endpoints: []adapter.Endpoint{ep}},
	}
	router := proxyRouter(server, nil)

	emptyReq := httptest.NewRequest(http.MethodPost, "/l3-test/routes", strings.NewReader("{}"))
	emptyReq = withProxyRouteContext(emptyReq, "l3-test")
	emptyReq.Header.Set("Content-Type", "application/json")
	emptyRec := httptest.NewRecorder()
	router.ServeHTTP(emptyRec, emptyReq)
	if emptyRec.Code != http.StatusBadRequest {
		t.Fatalf("empty payload must fail with 400, got %d (%s)", emptyRec.Code, emptyRec.Body.String())
	}
	if !strings.Contains(emptyRec.Body.String(), "peer_id must be non-zero") {
		t.Fatalf("expected detailed validation message, got %s", emptyRec.Body.String())
	}

	validReq := httptest.NewRequest(http.MethodPost, "/l3-test/routes", strings.NewReader(`{"peer_id":101,"user":"owner-a","filter_source_ips":["10.201.0.0/24"],"allowed_ips":["10.201.0.0/24"]}`))
	validReq = withProxyRouteContext(validReq, "l3-test")
	validReq.Header.Set("Content-Type", "application/json")
	validRec := httptest.NewRecorder()
	router.ServeHTTP(validRec, validReq)
	if validRec.Code != http.StatusOK {
		t.Fatalf("valid payload must pass with 200, got %d (%s)", validRec.Code, validRec.Body.String())
	}

	m := ep.SnapshotMetrics()
	if m.ControlErrors == 0 || m.ControlUpsertOK == 0 {
		t.Fatalf("expected both failed and successful control-plane operations, got %+v", m)
	}
}

func TestL3RouterControlAPIStrictValidationRejectsUnknownFields(t *testing.T) {
	ep := newTestL3Endpoint("l3-test")
	server := &Server{
		outbound:                 &testOutboundManager{outbounds: map[string]adapter.Outbound{}},
		endpoint:                 &testEndpointManager{endpoints: []adapter.Endpoint{ep}},
		l3RouterStrictValidation: true,
	}
	router := proxyRouter(server, nil)

	req := httptest.NewRequest(http.MethodPost, "/l3-test/routes", strings.NewReader(`{"peer_id":101,"user":"owner-a","allowed_ips":["10.201.0.0/24"],"unknown_field":true}`))
	req = withProxyRouteContext(req, "l3-test")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("strict mode must reject unknown fields, got %d (%s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(strings.ToLower(rec.Body.String()), "unknown") {
		t.Fatalf("expected unknown field message, got %s", rec.Body.String())
	}
}

func TestL3RouterProxyMetricsEndpoint(t *testing.T) {
	ep := newTestL3Endpoint("l3-test")
	server := &Server{
		outbound: &testOutboundManager{outbounds: map[string]adapter.Outbound{}},
		endpoint: &testEndpointManager{endpoints: []adapter.Endpoint{ep}},
	}
	router := proxyRouter(server, nil)

	req := httptest.NewRequest(http.MethodGet, "/l3-test/metrics", nil)
	req = withProxyRouteContext(req, "l3-test")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("metrics request must pass with 200, got %d (%s)", rec.Code, rec.Body.String())
	}
}

func withProxyRouteContext(req *http.Request, name string) *http.Request {
	routeCtx := chi.NewRouteContext()
	routeCtx.URLParams.Add("name", name)
	return req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, routeCtx))
}
