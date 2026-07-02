//go:build masque_ref

package main

import (
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"

	qmasque "github.com/quic-go/masque-go"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/yosida95/uritemplate/v3"
)

func main() {
	certFile := env("MASQUE_TLS_CERT", "/etc/sing-box/cert.pem")
	keyFile := env("MASQUE_TLS_KEY", "/etc/sing-box/key.pem")
	listenPort := envInt("MASQUE_LISTEN_PORT", 8443)

	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		log.Fatalf("load tls: %v", err)
	}
	tlsConf := &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{http3.NextProtoH3},
	}

	quicConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: listenPort})
	if err != nil {
		log.Fatalf("listen quic udp: %v", err)
	}
	defer quicConn.Close()

	host := env("MASQUE_PROXY_HOST", "masque-perf-masque-go-proxy")
	raw := fmt.Sprintf("https://%s:%d/masque/udp/{target_host}/{target_port}", host, listenPort)
	template, err := uritemplate.New(raw)
	if err != nil {
		log.Fatalf("template: %v", err)
	}

	proxy := &qmasque.Proxy{}
	mux := http.NewServeMux()
	mux.HandleFunc("/masque/udp/{target_host}/{target_port}", func(w http.ResponseWriter, r *http.Request) {
		req, err := qmasque.ParseRequest(r, template)
		if err != nil {
			var perr *qmasque.RequestParseError
			if errors.As(err, &perr) {
				w.WriteHeader(perr.HTTPStatus)
				return
			}
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if err := proxy.Proxy(w, req); err != nil {
			log.Printf("proxy: %v", err)
		}
	})

	server := http3.Server{
		TLSConfig:       tlsConf,
		QUICConfig:      &quic.Config{EnableDatagrams: true},
		EnableDatagrams: true,
		Handler:         mux,
	}
	log.Printf("masque-go docker proxy listening udp :%d template=%s", listenPort, raw)
	log.Fatal(server.Serve(quicConn))
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envInt(key string, def int) int {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	return n
}
