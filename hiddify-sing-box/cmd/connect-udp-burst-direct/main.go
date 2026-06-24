// connect-udp-burst-direct: CoreClientFactory CONNECT-UDP burst (no sing-box SOCKS) for docker bisect.
// Usage: connect-udp-burst-direct <server_host> <server_port> <sink_host> <sink_port> <h2|h3> <duration_sec> <target_mbit>
package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"os"
	"strconv"
	"time"

	"github.com/sagernet/sing-box/option"
	TM "github.com/sagernet/sing-box/transport/masque"
	"github.com/sagernet/sing-box/transport/masque/connectudp"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/yosida95/uritemplate/v3"

	_ "github.com/sagernet/sing-box/internal/http2xconnect"
)

func main() {
	if len(os.Args) < 8 {
		fmt.Fprintf(os.Stderr, "usage: connect-udp-burst-direct server_host server_port sink_host sink_port h2|h3 duration_sec target_mbit\n")
		os.Exit(2)
	}
	serverHost := os.Args[1]
	serverPort, err := strconv.Atoi(os.Args[2])
	if err != nil || serverPort <= 0 {
		fmt.Fprintf(os.Stderr, "invalid server_port\n")
		os.Exit(2)
	}
	sinkHost := os.Args[3]
	sinkPort, err := strconv.Atoi(os.Args[4])
	if err != nil || sinkPort <= 0 {
		fmt.Fprintf(os.Stderr, "invalid sink_port\n")
		os.Exit(2)
	}
	layer := os.Args[5]
	duration, err := strconv.ParseFloat(os.Args[6], 64)
	if err != nil || duration <= 0 {
		fmt.Fprintf(os.Stderr, "invalid duration\n")
		os.Exit(2)
	}
	targetMbit, err := strconv.ParseFloat(os.Args[7], 64)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid target_mbit\n")
		os.Exit(2)
	}

	payloadLen := connectudp.DefaultBenchUDPPayloadLen
	if v := os.Getenv("BENCH_UDP_PAYLOAD_LEN"); v != "" {
		payloadLen, _ = strconv.Atoi(v)
	}

	sni := serverHost
	if v := os.Getenv("MASQUE_TLS_SERVER_NAME"); v != "" {
		sni = v
	}
	tplRaw := fmt.Sprintf("https://%s:%d/masque/udp/{target_host}/{target_port}", serverHost, serverPort)
	if _, err := uritemplate.New(tplRaw); err != nil {
		fmt.Printf("RESULT_UDP_SEND_ERR=template: %v\n", err)
		os.Exit(1)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(duration*4+30)*time.Second)
	defer cancel()

	baseDial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, addr)
	}
	opts := TM.ClientOptions{
		Server:              serverHost,
		ServerPort:          uint16(serverPort),
		TransportMode:       option.MasqueTransportModeConnectUDP,
		TemplateUDP:         tplRaw,
		MasqueQUICCryptoTLS: &tls.Config{InsecureSkipVerify: true, ServerName: sni},
		TCPDial:             baseDial,
	}
	switch layer {
	case "h2", "H2":
		opts.MasqueEffectiveHTTPLayer = option.MasqueHTTPLayerH2
	case "h3", "H3":
		opts.MasqueEffectiveHTTPLayer = option.MasqueHTTPLayerH3
	default:
		fmt.Printf("RESULT_UDP_SEND_ERR=unknown layer %q\n", layer)
		os.Exit(1)
	}

	session, err := (TM.CoreClientFactory{}).NewSession(ctx, opts)
	if err != nil {
		fmt.Printf("RESULT_UDP_SEND_ERR=session: %v\n", err)
		os.Exit(1)
	}
	defer func() { _ = session.Close() }()

	dest := M.ParseSocksaddrHostPort(sinkHost, uint16(sinkPort))
	pkt, err := session.ListenPacket(ctx, dest)
	if err != nil {
		fmt.Printf("RESULT_UDP_SEND_ERR=listen: %v\n", err)
		os.Exit(1)
	}
	defer func() { _ = pkt.Close() }()

	sinkUDP := dest.UDPAddr()
	runID := uint32(0xD1BE0000)
	if v := os.Getenv("BENCH_UDP_RUN_ID"); v != "" {
		u, _ := strconv.ParseUint(v, 10, 32)
		runID = uint32(u)
	}

	start := time.Now()
	deadline := start.Add(time.Duration(duration * float64(time.Second)))
	var seq uint64
	var sent, sentBytes int
	var paceSlot time.Time
	payload := make([]byte, payloadLen)

	for time.Now().Before(deadline) {
		p := connectudp.BuildProbePayload(seq, runID, payloadLen)
		copy(payload, p)
		n, werr := pkt.WriteTo(payload, sinkUDP)
		if werr != nil {
			fmt.Printf("RESULT_UDP_SEND_ERR=write seq=%d: %v\n", seq, werr)
			os.Exit(1)
		}
		sentBytes += n
		sent++
		seq++
		if targetMbit > 0 {
			connectudp.PaceSleepUntil(&paceSlot, payloadLen, targetMbit)
		}
	}
	sendElapsed := time.Since(start).Seconds()
	connectudp.FlushPacketConnWrites(pkt)
	if err := connectudp.DrainPacketConnUpload(pkt, connectudp.DefaultUploadDrainTimeout); err != nil {
		fmt.Printf("RESULT_UDP_SEND_ERR=upload_drain: %v\n", err)
		os.Exit(1)
	}
	time.Sleep(200 * time.Millisecond)
	if sendElapsed < 1e-9 {
		sendElapsed = 1e-9
	}

	fmt.Printf("RESULT_UDP_RUN_ID=%d\n", runID)
	fmt.Printf("RESULT_UDP_SENT_BYTES=%d\n", sentBytes)
	fmt.Printf("RESULT_UDP_SENT_PKTS=%d\n", sent)
	fmt.Printf("RESULT_UDP_SEND_SEC=%.3f\n", sendElapsed)
}
