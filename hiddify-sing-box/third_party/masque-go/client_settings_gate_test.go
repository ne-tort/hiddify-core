package masque_test

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"sync/atomic"
	"testing"

	"github.com/quic-go/masque-go"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/stretchr/testify/require"
	"github.com/yosida95/uritemplate/v3"
)

// TestClientWaitsForH3SettingsBeforeCONNECTUDP (RFC-M §8.5) locks dialStream SETTINGS gate before stream handoff.
func TestClientWaitsForH3SettingsBeforeCONNECTUDP(t *testing.T) {
	t.Parallel()

	ln := newUDPConnLocalhost(t)
	mux := http.NewServeMux()
	mux.HandleFunc("/masque", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	server := http3.Server{
		TLSConfig:       tlsConf,
		QUICConfig:      &quic.Config{EnableDatagrams: true},
		EnableDatagrams: true,
		Handler:         mux,
	}
	t.Cleanup(func() { _ = server.Close() })
	go func() { _ = server.Serve(ln) }()

	port := ln.LocalAddr().(*net.UDPAddr).Port
	template := uritemplate.MustNew(fmt.Sprintf("https://localhost:%d/masque?h={target_host}&p={target_port}", port))

	var hookSettingsOK atomic.Bool
	masque.SetDialUDPTestHook(func(context.Context) {
		hookSettingsOK.Store(true)
	})
	t.Cleanup(masque.ClearDialUDPTestHook)

	cl := masque.Client{
		TLSClientConfig: &tls.Config{
			ClientCAs:          certPool,
			NextProtos:         []string{http3.NextProtoH3},
			InsecureSkipVerify: true,
		},
	}
	t.Cleanup(func() { _ = cl.Close() })

	pc, _, err := cl.Dial(context.Background(), template, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9})
	require.NoError(t, err)
	require.NotNil(t, pc)
	require.True(t, hookSettingsOK.Load(), "CONNECT-UDP must complete only after server SETTINGS (incl. datagrams)")
	_ = pc.Close()
}

func TestClientRejectsServerWithoutH3DatagramSetting(t *testing.T) {
	t.Parallel()

	ln := newUDPConnLocalhost(t)
	mux := http.NewServeMux()
	mux.HandleFunc("/masque", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	server := http3.Server{
		TLSConfig:       tlsConf,
		QUICConfig:      &quic.Config{EnableDatagrams: false},
		EnableDatagrams: false,
		Handler:         mux,
	}
	t.Cleanup(func() { _ = server.Close() })
	go func() { _ = server.Serve(ln) }()

	port := ln.LocalAddr().(*net.UDPAddr).Port
	template := uritemplate.MustNew(fmt.Sprintf("https://localhost:%d/masque?h={target_host}&p={target_port}", port))

	cl := masque.Client{
		TLSClientConfig: &tls.Config{
			ClientCAs:          certPool,
			NextProtos:         []string{http3.NextProtoH3},
			InsecureSkipVerify: true,
		},
	}
	t.Cleanup(func() { _ = cl.Close() })

	_, _, err := cl.Dial(context.Background(), template, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9})
	require.Error(t, err)
	require.Contains(t, err.Error(), "didn't enable Datagrams")
}
