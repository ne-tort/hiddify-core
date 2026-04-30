package masque_test

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/quic-go/masque-go"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/stretchr/testify/require"
	"github.com/yosida95/uritemplate/v3"
)

const (
	stressBytesTotal = 500 * 1024 * 1024 // 500 MB
	stressPayloadLen = 1200
)

func TestStress500MBBidirectional(t *testing.T) {
	if os.Getenv("MASQUE_STRESS") != "1" {
		t.Skip("set MASQUE_STRESS=1 to run heavy local stress test")
	}

	runMode := func(t *testing.T, name string, targetMbit int) {
		remoteServerConn := runEchoServer(t, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
		defer remoteServerConn.Close()

		conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
		require.NoError(t, err)
		defer conn.Close()

		template := uritemplate.MustNew(fmt.Sprintf("https://localhost:%d/masque?h={target_host}&p={target_port}", conn.LocalAddr().(*net.UDPAddr).Port))
		mux := http.NewServeMux()
		server := http3.Server{
			TLSConfig:       tlsConf,
			QUICConfig:      &quic.Config{EnableDatagrams: true},
			EnableDatagrams: true,
			Handler:         mux,
		}
		defer server.Close()
		proxy := masque.Proxy{}
		defer proxy.Close()
		mux.HandleFunc("/masque", func(w http.ResponseWriter, r *http.Request) {
			req, err := masque.ParseRequest(r, template)
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			_ = proxy.Proxy(w, req)
		})
		go func() { _ = server.Serve(conn) }()

		cl := masque.Client{
			TLSClientConfig: &tls.Config{
				ClientCAs:          certPool,
				NextProtos:         []string{http3.NextProtoH3},
				InsecureSkipVerify: true,
			},
		}
		defer cl.Close()

		proxiedConn, _, err := cl.Dial(context.Background(), template, remoteServerConn.LocalAddr().(*net.UDPAddr))
		require.NoError(t, err)
		defer proxiedConn.Close()

		payload := make([]byte, stressPayloadLen)
		start := time.Now()
		deadline := start.Add(10 * time.Minute)
		require.NoError(t, proxiedConn.SetDeadline(deadline))

		var sentBytes, recvBytes int64
		totalPackets := stressBytesTotal / stressPayloadLen
		for seq := 0; seq < totalPackets; seq++ {
			binary.BigEndian.PutUint32(payload[:4], uint32(seq))
			_, err = proxiedConn.WriteTo(payload, remoteServerConn.LocalAddr())
			require.NoError(t, err)
			sentBytes += stressPayloadLen

			buf := make([]byte, stressPayloadLen+64)
			n, _, err := proxiedConn.ReadFrom(buf)
			require.NoError(t, err)
			require.Equal(t, stressPayloadLen, n)
			require.Equal(t, uint32(seq), binary.BigEndian.Uint32(buf[:4]))
			recvBytes += int64(n)

			if targetMbit > 0 {
				targetBytesPerSec := float64(targetMbit*1024*1024) / 8.0
				expectedElapsed := time.Duration(float64(sentBytes)/targetBytesPerSec) * time.Second
				actualElapsed := time.Since(start)
				if expectedElapsed > actualElapsed {
					time.Sleep(expectedElapsed - actualElapsed)
				}
			}
		}

		elapsed := time.Since(start).Seconds()
		txMbit := (float64(sentBytes) * 8 / 1024 / 1024) / elapsed
		rxMbit := (float64(recvBytes) * 8 / 1024 / 1024) / elapsed
		lossPercent := 0.0
		if recvBytes < sentBytes {
			lossPercent = (float64(sentBytes-recvBytes) / float64(sentBytes)) * 100
		}
		t.Logf("[%s] tx=%.2f Mbit/s rx=%.2f Mbit/s sent=%d recv=%d loss=%.4f%% elapsed=%.2fs",
			name, txMbit, rxMbit, sentBytes, recvBytes, lossPercent, elapsed)
	}

	shapedMbit := 50
	if raw := os.Getenv("MASQUE_STRESS_SHAPED_MBIT"); raw != "" {
		if v, err := strconv.Atoi(raw); err == nil && v > 0 {
			shapedMbit = v
		}
	}

	t.Run("max_speed", func(t *testing.T) { runMode(t, "max_speed", 0) })
	t.Run("shaped_speed", func(t *testing.T) { runMode(t, "shaped_speed", shapedMbit) })
}

