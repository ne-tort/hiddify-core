package masque

import (
	"io"
	"net"
	"testing"
)

const (
	cpuSiteConnectIPL1PipeUpload   = "L1-connect-ip-pipe-upload"
	cpuSiteConnectIPL1PipeDownload = "L1-connect-ip-pipe-download"
)

func init() {
	cpuSiteCodeRef[cpuSiteConnectIPL1PipeUpload] = "connectip netstack+forwarder TCP upload (prodInstantPacketLink)"
	cpuSiteCodeRef[cpuSiteConnectIPL1PipeDownload] = "connectip netstack+forwarder TCP download (prodInstantPacketLink)"
}

func connectIPCPUBenchPayload() []byte {
	payload := make([]byte, connectUDPCPUBenchIterBytes)
	for i := range payload {
		payload[i] = byte(i % 251)
	}
	return payload
}

func setupConnectIPL1PipeUploadCPUBench(t *testing.T) (net.Conn, []byte) {
	t.Helper()
	h := startConnectIPUploadHarness(t, prodInstantPacketLink{})
	t.Cleanup(func() { h.close() })
	conn := h.dialRemote(t)
	t.Cleanup(func() { _ = conn.Close() })
	return conn, connectIPCPUBenchPayload()
}

func setupConnectIPL1PipeDownloadCPUBench(t *testing.T) (net.Conn, []byte) {
	t.Helper()
	h := startConnectIPDownloadHarness(t, prodInstantPacketLink{})
	t.Cleanup(func() { h.close() })
	conn := h.dialRemote(t)
	t.Cleanup(func() { _ = conn.Close() })
	buf := make([]byte, connectUDPCPUBenchIterBytes+64)
	return conn, buf
}

func benchConnectIPCPUUploadN(tb testing.TB, conn net.Conn, payload []byte, maxBytes int64) int64 {
	tb.Helper()
	var sent int64
	for sent < maxBytes {
		n, err := conn.Write(payload)
		if err != nil {
			tb.Fatal(err)
		}
		sent += int64(n)
	}
	return sent
}

func benchConnectIPCPUDownloadN(tb testing.TB, conn net.Conn, buf []byte, maxBytes int64) int64 {
	tb.Helper()
	var received int64
	for received < maxBytes {
		n, err := conn.Read(buf)
		if err != nil {
			if err == io.EOF && received > 0 {
				break
			}
			tb.Fatal(err)
		}
		received += int64(n)
	}
	return received
}
