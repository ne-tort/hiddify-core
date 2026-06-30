//go:build masque_inttest_heavy

package inttest_test

import (
	"testing"

	masque "github.com/sagernet/sing-box/transport/masque"
)

func TestConnectIPL3HostEgressIperfReverse(t *testing.T) {
	t.Parallel()
	masque.InttestConnectIPL3HostEgressIperfReverse(t)
}
