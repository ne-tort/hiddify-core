package masquetls

import (
	"bytes"
	"context"
	"crypto/tls"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/stretchr/testify/require"
)

func TestSynth_ALPNNegotiatedH2(t *testing.T) {
	t.Parallel()
	cert, _, _ := generateTestTLSMaterial(t, testTLSHost)
	hello := &helloCapture{}
	clientRaw, _ := startPipeTLSServer(t, &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"h2", "http/1.1"},
		MinVersion:   tls.VersionTLS12,
	}, hello)

	cap := &captureConn{Conn: clientRaw}
	logger := log.NewNOPFactory().Logger()
	dialTLS, err := BuildTCPDialTLS(context.Background(), logger, testTLSHost, &option.OutboundTLSOptions{
		Enabled:    true,
		Insecure:   true,
		ServerName: testTLSHost,
		ALPN:       []string{"h2", "http/1.1"},
	}, option.MasqueHTTPLayerH2)
	require.NoError(t, err)

	tlsConn, err := dialTLS(context.Background(), cap, nil, testTLSHost+":443")
	require.NoError(t, err)
	defer tlsConn.Close()

	cs, ok := tlsConn.(interface{ ConnectionState() tls.ConnectionState })
	require.True(t, ok, "TLS conn must expose ConnectionState")
	require.Equal(t, "h2", cs.ConnectionState().NegotiatedProtocol)

	chi := hello.get()
	require.NotNil(t, chi, "server must see ClientHello")
	require.Contains(t, chi.SupportedProtos, "h2")
	require.Equal(t, testTLSHost, chi.ServerName)
}

func TestSynth_SNIWrongHostFailsWithoutInsecure(t *testing.T) {
	t.Parallel()
	cert, certPEM, _ := generateTestTLSMaterial(t, testTLSHost)
	clientRaw, serverDone := startPipeTLSServer(t, &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"h2"},
		MinVersion:   tls.VersionTLS12,
	}, nil)

	logger := log.NewNOPFactory().Logger()
	dialTLS, err := BuildTCPDialTLS(context.Background(), logger, "evil.example.com", &option.OutboundTLSOptions{
		Enabled:     true,
		Insecure:    false,
		ServerName:  "evil.example.com",
		ALPN:        []string{"h2"},
		Certificate: certPEM,
	}, option.MasqueHTTPLayerH2)
	require.NoError(t, err)

	_, err = dialTLS(context.Background(), clientRaw, nil, "evil.example.com:443")
	require.Error(t, err, "wrong SNI against cert must fail when insecure=false")
	select {
	case <-serverDone:
	case <-time.After(2 * time.Second):
	}
}

func TestSynth_InsecureBypassesCertVerify(t *testing.T) {
	t.Parallel()
	cert, _, _ := generateTestTLSMaterial(t, testTLSHost)
	clientRaw, _ := startPipeTLSServer(t, &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"h2"},
		MinVersion:   tls.VersionTLS12,
	}, nil)

	logger := log.NewNOPFactory().Logger()
	dialTLS, err := BuildTCPDialTLS(context.Background(), logger, "other.example.com", &option.OutboundTLSOptions{
		Enabled:    true,
		Insecure:   true,
		ServerName: "other.example.com",
		ALPN:       []string{"h2"},
	}, option.MasqueHTTPLayerH2)
	require.NoError(t, err)

	tlsConn, err := dialTLS(context.Background(), clientRaw, nil, "other.example.com:443")
	require.NoError(t, err)
	_ = tlsConn.Close()
}

func TestSynth_MixedCaseSNI_OnWireAndHello(t *testing.T) {
	t.Parallel()
	cert, _, _ := generateTestTLSMaterial(t, testTLSHost)
	hello := &helloCapture{}
	clientRaw, _ := startPipeTLSServer(t, &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"h2"},
		MinVersion:   tls.VersionTLS12,
	}, hello)

	cap := &captureConn{Conn: clientRaw}
	logger := log.NewNOPFactory().Logger()
	dialTLS, err := BuildTCPDialTLS(context.Background(), logger, testTLSHost, &option.OutboundTLSOptions{
		Enabled:    true,
		Insecure:   true,
		ServerName: testTLSHost,
		ALPN:       []string{"h2"},
		TLSTricks:  &option.TLSTricksOptions{MixedCaseSNI: true},
	}, option.MasqueHTTPLayerH2)
	require.NoError(t, err)

	tlsConn, err := dialTLS(context.Background(), cap, nil, testTLSHost+":443")
	require.NoError(t, err)
	_ = tlsConn.Close()

	chi := hello.get()
	require.NotNil(t, chi)
	require.True(t, strings.EqualFold(chi.ServerName, testTLSHost))
	require.NotEqual(t, testTLSHost, chi.ServerName, "mixedcase must change wire SNI casing")

	wire := cap.joined()
	require.True(t, bytes.Contains(wire, []byte(chi.ServerName)), "captured ClientHello must contain exact mixedcase SNI bytes")
}

func TestSynth_RecordFragment_SplitsTLSRecords(t *testing.T) {
	t.Parallel()
	cert, _, _ := generateTestTLSMaterial(t, testTLSHost)
	clientRaw, _ := startPipeTLSServer(t, &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"h2"},
		MinVersion:   tls.VersionTLS12,
	}, nil)

	capFrag := &captureConn{Conn: clientRaw}
	logger := log.NewNOPFactory().Logger()
	dialFrag, err := BuildTCPDialTLS(context.Background(), logger, testTLSHost, &option.OutboundTLSOptions{
		Enabled:        true,
		Insecure:       true,
		ServerName:     testTLSHost,
		ALPN:           []string{"h2"},
		RecordFragment: true,
	}, option.MasqueHTTPLayerH2)
	require.NoError(t, err)
	tlsConn, err := dialFrag(context.Background(), capFrag, nil, testTLSHost+":443")
	require.NoError(t, err)
	_ = tlsConn.Close()

	fragRecords := countTLSRecords(capFrag.joined())
	require.Greater(t, fragRecords, 1, "record_fragment must emit >1 TLS records wrapping ClientHello")

	cert2, _, _ := generateTestTLSMaterial(t, testTLSHost)
	clientRaw2, _ := startPipeTLSServer(t, &tls.Config{
		Certificates: []tls.Certificate{cert2},
		NextProtos:   []string{"h2"},
		MinVersion:   tls.VersionTLS12,
	}, nil)
	capPlain := &captureConn{Conn: clientRaw2}
	dialPlain, err := BuildTCPDialTLS(context.Background(), logger, testTLSHost, &option.OutboundTLSOptions{
		Enabled:    true,
		Insecure:   true,
		ServerName: testTLSHost,
		ALPN:       []string{"h2"},
	}, option.MasqueHTTPLayerH2)
	require.NoError(t, err)
	tlsConn2, err := dialPlain(context.Background(), capPlain, nil, testTLSHost+":443")
	require.NoError(t, err)
	_ = tlsConn2.Close()

	require.NotEmpty(t, capPlain.writes)
	require.Equal(t, 1, countTLSRecords(capPlain.writes[0]), "plain ClientHello should be one TLS record in first write")
}

func TestSynth_EmptyALPNDefaultsToH2OnWire(t *testing.T) {
	t.Parallel()
	cert, _, _ := generateTestTLSMaterial(t, testTLSHost)
	hello := &helloCapture{}
	clientRaw, _ := startPipeTLSServer(t, &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"h2", "http/1.1"},
		MinVersion:   tls.VersionTLS12,
	}, hello)

	logger := log.NewNOPFactory().Logger()
	dialTLS, err := BuildTCPDialTLS(context.Background(), logger, testTLSHost, &option.OutboundTLSOptions{
		Enabled:    true,
		Insecure:   true,
		ServerName: testTLSHost,
	}, option.MasqueHTTPLayerH2)
	require.NoError(t, err)
	tlsConn, err := dialTLS(context.Background(), clientRaw, nil, testTLSHost+":443")
	require.NoError(t, err)
	_ = tlsConn.Close()

	chi := hello.get()
	require.NotNil(t, chi)
	require.Contains(t, chi.SupportedProtos, "h2")
}

func TestSynth_QUICStrip_NoMixedCaseOrUTLSOnConfig(t *testing.T) {
	t.Parallel()
	logger := log.NewNOPFactory().Logger()
	cfg, err := BuildQUICStdTLSConfig(context.Background(), logger, testTLSHost, &option.OutboundTLSOptions{
		Enabled:        true,
		Insecure:       true,
		ServerName:     testTLSHost,
		UTLS:           &option.OutboundUTLSOptions{Enabled: true, Fingerprint: "chrome"},
		TLSTricks:      &option.TLSTricksOptions{MixedCaseSNI: true},
		RecordFragment: true,
		Fragment:       true,
	}, option.MasqueHTTPLayerAuto)
	require.NoError(t, err)
	require.Equal(t, testTLSHost, cfg.ServerName, "QUIC path must not apply mixedcase")
	require.Contains(t, cfg.NextProtos, "h3")
}
