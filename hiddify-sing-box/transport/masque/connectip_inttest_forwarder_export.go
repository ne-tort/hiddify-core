package masque

// Inttest forwarder gate runners (W-IP-6 IP-6-PR3). Harness in connectip_forwarder_harness.go.

import "testing"

func InttestConnectIPTCPForwarderPipeSYNHandshake(t *testing.T) {
	t.Helper()
	gateConnectIPTCPForwarderPipeSYNHandshake(t)
}

func InttestConnectIPTCPForwarderDownloadWindowedLinkThroughput(t *testing.T) {
	t.Helper()
	gateConnectIPTCPForwarderDownloadWindowedLinkThroughput(t)
}

func InttestConnectIPTCPForwarderPipeUploadThenDownload(t *testing.T) {
	t.Helper()
	gateConnectIPTCPForwarderPipeUploadThenDownload(t)
}

func InttestConnectIPTunForwarderPostUploadServerRecycle(t *testing.T) {
	t.Helper()
	gateConnectIPTunForwarderPostUploadServerRecycle(t)
}

func InttestConnectIPTCPNetstackHandshakeWithForwarderSynAck(t *testing.T) {
	t.Helper()
	gateConnectIPTCPNetstackHandshakeWithForwarderSynAck(t)
}

func InttestConnectIPTCPForwarderSYNRetransmitSingleDial(t *testing.T) {
	t.Helper()
	gateConnectIPTCPForwarderSYNRetransmitSingleDial(t)
}

func InttestConnectIPTCPForwarderPipeBulk(t *testing.T) {
	t.Helper()
	gateConnectIPTCPForwarderPipeBulk(t)
}

func InttestConnectIPTCPForwarderWriteQueueDepthWindowedLink(t *testing.T) {
	t.Helper()
	gateConnectIPTCPForwarderWriteQueueDepthWindowedLink(t)
}

func InttestForwarderRestartReadinessSynDialAfterUpload(t *testing.T) {
	t.Helper()
	gateForwarderRestartReadinessSynDialAfterUpload(t)
}

func InttestConnectIPTCPForwarderServerReadBenign0x100NotFatal(t *testing.T) {
	t.Helper()
	gateConnectIPTCPForwarderServerReadBenign0x100NotFatal(t)
}

func InttestConnectIPTCPForwarderWritePacketFailThenOKNoSilentDrop(t *testing.T) {
	t.Helper()
	gateConnectIPTCPForwarderWritePacketFailThenOKNoSilentDrop(t)
}
