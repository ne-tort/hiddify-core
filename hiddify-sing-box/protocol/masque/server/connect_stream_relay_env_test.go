package server

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
	"github.com/yosida95/uritemplate/v3"
)

// serverH3RelayResponse implements stream.RelayCONNECTH3Leg for in-process server handler benches (S77).
type serverH3RelayResponse struct {
	leg io.ReadWriteCloser
}

func (m *serverH3RelayResponse) MasqueRelayCONNECTH3Leg() io.ReadWriteCloser {
	return m.leg
}

func (m *serverH3RelayResponse) Header() http.Header { return make(http.Header) }
func (m *serverH3RelayResponse) Write(b []byte) (int, error) {
	if m.leg != nil {
		return m.leg.Write(b)
	}
	return len(b), nil
}
func (m *serverH3RelayResponse) WriteHeader(int) {}
func (m *serverH3RelayResponse) Flush()          {}

func benchServerHandlerDownloadWriteToMbps(t *testing.T, link serverHandlerLink, env map[string]string, h3Leg bool) (int64, float64) {
	t.Helper()
	t.Setenv("MASQUE_RELAY_TCP_STREAM_HIJACK", "")
	t.Setenv("MASQUE_RELAY_TCP_LEGACY", "")
	for k, v := range env {
		t.Setenv(k, v)
	}

	ln := startServerHandlerDownloadTarget(t)
	port := ln.Addr().(*net.TCPAddr).Port
	template := uritemplate.MustNew("https://masque.local/masque/tcp/{target_host}/{target_port}")
	host := TCPConnectHost{
		Options: option.MasqueEndpointOptions{AllowPrivateTargets: true},
		Dialer:  net.Dialer{Timeout: 5 * time.Second},
		Authorize: func(*http.Request) bool {
			return true
		},
		AuthorityMatches: func(_, _ string, _ bool) bool { return true },
	}

	clientLeg, serverLeg := net.Pipe()
	var resp http.ResponseWriter = &streamFlusherWriter{conn: serverLeg}
	if h3Leg {
		resp = &serverH3RelayResponse{leg: serverLeg}
	}

	path := "/masque/tcp/127.0.0.1/" + strconv.Itoa(port)
	ctx, cancel := context.WithCancel(context.Background())
	uploadR, uploadW := io.Pipe()
	t.Cleanup(func() {
		cancel()
		_ = uploadW.Close()
		_ = uploadR.Close()
	})
	req := httptest.NewRequest(http.MethodConnect, path, uploadR)
	req = req.WithContext(ctx)
	req.Host = "masque.local"
	req.RequestURI = "https://masque.local" + path
	req.Header.Set(":protocol", "HTTP/2")

	handlerDone := make(chan struct{})
	go func() {
		defer close(handlerDone)
		HandleTCPConnectRequest(host, resp, req, template, true)
		_ = serverLeg.Close()
	}()

	client := link.wrap(serverConnWriterTo{clientLeg})
	n, mbps, err := measureServerHandlerDownloadWriteToMbps(client, serverLocalizeBenchDur)
	cancel()
	_ = uploadW.Close()
	_ = clientLeg.Close()
	select {
	case <-handlerDone:
	case <-time.After(3 * time.Second):
		t.Fatal("handler did not finish after bench cancel")
	}
	if err != nil && n == 0 {
		t.Fatalf("WriteTo download measure: %v", err)
	}
	return n, mbps
}

// TestRelayEnvMatrixSTREAM_HIJACKDownload (S77): server HandleTCPConnectRequest × STREAM_HIJACK × download bands.
func TestRelayEnvMatrixSTREAM_HIJACKDownload(t *testing.T) {
	cases := []struct {
		name     string
		env      map[string]string
		h3Leg    bool
		link     serverHandlerLink
		wantFast bool
		wantBand bool
		wantKPI  bool
	}{
		{
			name:     "stream_hijack_on_instant",
			env:      map[string]string{"MASQUE_RELAY_TCP_STREAM_HIJACK": "1"},
			h3Leg:    true,
			link:     serverInstantLink{},
			wantFast: true,
		},
		{
			name:     "stream_hijack_on_windowed",
			env:      map[string]string{"MASQUE_RELAY_TCP_STREAM_HIJACK": "1"},
			h3Leg:    true,
			link:     serverWindowedLink{},
			wantBand: true,
		},
		{
			name: "stream_hijack_on_windowed_prod_client",
			env: map[string]string{
				"MASQUE_RELAY_TCP_STREAM_HIJACK": "1",
			},
			h3Leg:    true,
			link:     serverProdWindowedLink{},
			wantKPI:  true,
		},
		{
			name: "stream_hijack_off_instant",
			env: map[string]string{
				"MASQUE_RELAY_TCP_STREAM_HIJACK": "0",
			},
			h3Leg:    false,
			link:     serverInstantLink{},
			wantFast: true,
		},
		{
			name: "stream_hijack_off_windowed",
			env: map[string]string{
				"MASQUE_RELAY_TCP_STREAM_HIJACK": "0",
			},
			h3Leg:    false,
			link:     serverWindowedLink{},
			wantBand: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			n, mbps := benchServerHandlerDownloadWriteToMbps(t, tc.link, tc.env, tc.h3Leg)
			t.Logf("%s: bytes=%d %.1f Mbit/s", tc.name, n, mbps)
			if n < serverLocalizeMinBytes {
				t.Fatalf("bytes=%d want >= %d", n, serverLocalizeMinBytes)
			}
			if tc.wantFast && mbps < serverLocalizeFastMbps {
				t.Fatalf("instant download slow: %.1f Mbit/s (want >= %.0f)", mbps, serverLocalizeFastMbps)
			}
			if tc.wantBand && (mbps < serverLocalizeCeilingMinMbps || mbps > serverLocalizeCeilingMaxMbps) {
				t.Fatalf("windowed download: %.1f Mbit/s (want %.0f–%.0f)",
					mbps, serverLocalizeCeilingMinMbps, serverLocalizeCeilingMaxMbps)
			}
			if tc.wantKPI {
				const kpiTargetMbps = 21.0
				if mbps <= kpiTargetMbps {
					t.Fatalf("windowed prod client download: %.1f Mbit/s (want > %.0f K-SRV1)", mbps, kpiTargetMbps)
				}
			}
		})
	}
}
