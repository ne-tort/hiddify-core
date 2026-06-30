//go:build masque_inttest_heavy

package inttest_test

import (
	"testing"

	masque "github.com/sagernet/sing-box/transport/masque"
)

func TestConnectIPForwarderIperfReverse(t *testing.T) {
	t.Parallel()
	masque.InttestConnectIPForwarderIperfReverse(t)
}

func TestConnectIPL3TunWriteIperfReverse(t *testing.T) {
	t.Parallel()
	masque.InttestConnectIPL3TunWriteIperfReverse(t)
}

func TestConnectIPL3TunWriteIperfReverseSplitParams(t *testing.T) {
	t.Parallel()
	masque.InttestConnectIPL3TunWriteIperfReverseSplitParams(t)
}

func TestConnectIPL3TunWriteBulkDownload(t *testing.T) {
	t.Parallel()
	masque.InttestConnectIPL3TunWriteBulkDownload(t)
}

func TestConnectIPL3TunWriteProbeThenIperfReverse(t *testing.T) {
	t.Parallel()
	masque.InttestConnectIPL3TunWriteProbeThenIperfReverse(t)
}

func TestConnectIPL3TunWriteNcZProbeThenIperfReverse(t *testing.T) {
	t.Parallel()
	masque.InttestConnectIPL3TunWriteNcZProbeThenIperfReverse(t)
}

func TestConnectIPL3TunWritePostNcUpload(t *testing.T) {
	t.Parallel()
	masque.InttestConnectIPL3TunWritePostNcUpload(t)
}

func TestConnectIPL3TunWriteUploadParamsAck(t *testing.T) {
	t.Parallel()
	masque.InttestConnectIPL3TunWriteUploadParamsAck(t)
}

func TestConnectIPL3TunWriteHostAckRelayIperfReverse(t *testing.T) {
	t.Parallel()
	masque.InttestConnectIPL3TunWriteHostAckRelayIperfReverse(t)
}
