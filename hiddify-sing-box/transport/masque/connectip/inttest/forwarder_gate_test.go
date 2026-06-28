package inttest_test

import (
	"testing"

	masque "github.com/sagernet/sing-box/transport/masque"
)

func TestConnectIPTCPForwarderPipeSYNHandshake(t *testing.T) {
	t.Parallel()
	masque.InttestConnectIPTCPForwarderPipeSYNHandshake(t)
}

func TestConnectIPTCPForwarderDownloadWindowedLinkThroughput(t *testing.T) {
	t.Parallel()
	masque.InttestConnectIPTCPForwarderDownloadWindowedLinkThroughput(t)
}

func TestConnectIPTCPForwarderPipeUploadThenDownload(t *testing.T) {
	t.Parallel()
	masque.InttestConnectIPTCPForwarderPipeUploadThenDownload(t)
}

func TestConnectIPTunForwarderPostUploadServerRecycle(t *testing.T) {
	masque.InttestConnectIPTunForwarderPostUploadServerRecycle(t)
}

func TestConnectIPTCPNetstackHandshakeWithForwarderSynAck(t *testing.T) {
	t.Parallel()
	masque.InttestConnectIPTCPNetstackHandshakeWithForwarderSynAck(t)
}

func TestConnectIPTCPForwarderSYNRetransmitSingleDial(t *testing.T) {
	t.Parallel()
	masque.InttestConnectIPTCPForwarderSYNRetransmitSingleDial(t)
}

func TestConnectIPTCPForwarderPipeBulk(t *testing.T) {
	t.Parallel()
	masque.InttestConnectIPTCPForwarderPipeBulk(t)
}

func TestConnectIPTCPForwarderWriteQueueDepthWindowedLink(t *testing.T) {
	t.Parallel()
	masque.InttestConnectIPTCPForwarderWriteQueueDepthWindowedLink(t)
}

func TestForwarderRestartReadinessSynDialAfterUpload(t *testing.T) {
	masque.InttestForwarderRestartReadinessSynDialAfterUpload(t)
}

func TestConnectIPTCPForwarderServerReadBenign0x100NotFatal(t *testing.T) {
	t.Parallel()
	masque.InttestConnectIPTCPForwarderServerReadBenign0x100NotFatal(t)
}

func TestConnectIPTCPForwarderWritePacketFailThenOKNoSilentDrop(t *testing.T) {
	t.Parallel()
	masque.InttestConnectIPTCPForwarderWritePacketFailThenOKNoSilentDrop(t)
}
