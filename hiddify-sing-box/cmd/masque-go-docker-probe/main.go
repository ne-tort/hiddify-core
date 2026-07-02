//go:build masque_ref

package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"hash/crc32"
	"math/rand"
	"net"
	"os"
	"strconv"
	"time"

	qmasque "github.com/quic-go/masque-go"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/sagernet/sing-box/transport/masque/connectudp"
	"github.com/yosida95/uritemplate/v3"
)

func main() {
	if len(os.Args) < 8 {
		fmt.Fprintf(os.Stderr, "usage: %s proxy_host proxy_port sink_host sink_port duration_sec target_mbit payload_len\n", os.Args[0])
		os.Exit(2)
	}
	proxyHost := os.Args[1]
	proxyPort, _ := strconv.Atoi(os.Args[2])
	sinkHost := os.Args[3]
	sinkPort, _ := strconv.Atoi(os.Args[4])
	durationSec, _ := strconv.ParseFloat(os.Args[5], 64)
	targetMbit, _ := strconv.ParseFloat(os.Args[6], 64)
	payloadLen, _ := strconv.Atoi(os.Args[7])
	if payloadLen <= 0 {
		payloadLen = connectudp.DefaultBenchUDPPayloadLen
	}
	if durationSec <= 0 {
		durationSec = 3
	}

	runID := uint32(crc32.ChecksumIEEE([]byte(fmt.Sprintf("%d", rand.Int63()))))
	raw := fmt.Sprintf("https://%s:%d/masque/udp/{target_host}/{target_port}", proxyHost, proxyPort)
	template, err := uritemplate.New(raw)
	if err != nil {
		fmt.Printf("RESULT_UDP_SEND_ERR=template: %v\n", err)
		os.Exit(1)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(durationSec*1000)*time.Millisecond+10*time.Second)
	defer cancel()

	client := &qmasque.Client{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			NextProtos:         []string{http3.NextProtoH3},
			ServerName:         proxyHost,
		},
		QUICConfig: &quic.Config{
			EnableDatagrams:   true,
			InitialPacketSize: 1350,
		},
	}
	defer client.Close()

	target := fmt.Sprintf("%s:%d", sinkHost, sinkPort)
	pkt, _, err := client.DialAddr(ctx, template, target)
	if err != nil {
		fmt.Printf("RESULT_UDP_SEND_ERR=dial: %v\n", err)
		os.Exit(1)
	}
	defer pkt.Close()

	sinkAddr := &net.UDPAddr{IP: net.ParseIP(sinkHost), Port: sinkPort}
	deadline := time.Now().Add(time.Duration(durationSec * float64(time.Second)))
	var seq uint64
	var sentBytes int
	var sentPkts int
	var paceSlot time.Time
	wallStart := time.Now()

	for time.Now().Before(deadline) {
		p := connectudp.BuildProbePayload(seq, runID, payloadLen)
		if _, err := pkt.WriteTo(p, sinkAddr); err != nil {
			fmt.Printf("RESULT_UDP_SEND_ERR=write: %v\n", err)
			os.Exit(1)
		}
		sentBytes += len(p)
		sentPkts++
		seq++
		connectudp.PaceSleepUntil(&paceSlot, payloadLen, targetMbit)
	}

	connectudp.FlushPacketConnWrites(pkt)
	_ = connectudp.DrainPacketConnUpload(pkt, 2*time.Second)
	elapsed := time.Since(wallStart).Seconds()
	if elapsed <= 0 {
		elapsed = durationSec
	}

	fmt.Printf("RESULT_UDP_RUN_ID=%d\n", runID)
	fmt.Printf("RESULT_UDP_SENT_BYTES=%d\n", sentBytes)
	fmt.Printf("RESULT_UDP_SENT_PKTS=%d\n", sentPkts)
	fmt.Printf("RESULT_UDP_SEND_SEC=%.3f\n", elapsed)
	fmt.Printf("RESULT_UDP_TARGET_MBIT=%g\n", targetMbit)
	if targetMbit <= 0 {
		fmt.Println("RESULT_UDP_SEND_MODE=burst")
	} else {
		fmt.Println("RESULT_UDP_SEND_MODE=paced")
	}
	if elapsed > 0 && sentBytes > 0 {
		mbps := float64(sentBytes*8) / elapsed / 1e6
		fmt.Printf("RESULT_UDP_SEND_MBIT=%.3f\n", mbps)
	}
}
