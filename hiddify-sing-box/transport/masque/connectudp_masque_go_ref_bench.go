//go:build masque_ref

package masque

import (
	"fmt"
	"net/http"
	"testing"

	qmasque "github.com/quic-go/masque-go"
	"github.com/yosida95/uritemplate/v3"
)

// registerMasqueGoRefUDPProxyHandler wires third_party masque-go Proxy (per-packet SendDatagram S2C).
func registerMasqueGoRefUDPProxyHandler(t testing.TB, mux *http.ServeMux, proxyPort int) {
	t.Helper()
	templateRaw := fmt.Sprintf("https://127.0.0.1:%d/masque/udp/{target_host}/{target_port}", proxyPort)
	udpTemplate, err := uritemplate.New(templateRaw)
	if err != nil {
		t.Fatalf("udp template: %v", err)
	}
	var udpProxy qmasque.Proxy
	t.Cleanup(func() { _ = udpProxy.Close() })
	mux.HandleFunc("/masque/udp/{target_host}/{target_port}", func(w http.ResponseWriter, r *http.Request) {
		req, err := qmasque.ParseRequest(r, udpTemplate)
		if err != nil {
			if pe, ok := err.(*qmasque.RequestParseError); ok {
				w.WriteHeader(pe.HTTPStatus)
				return
			}
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if err := udpProxy.Proxy(w, req); err != nil {
			w.WriteHeader(http.StatusBadGateway)
		}
	})
}

type connectUDPH3FountainBenchRow struct {
	label    string
	register func(testing.TB, *http.ServeMux, int)
}
