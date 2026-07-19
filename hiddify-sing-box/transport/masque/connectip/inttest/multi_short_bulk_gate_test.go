//go:build masque_inttest_heavy

package inttest_test

import (
	"testing"

	"github.com/sagernet/sing-box/transport/masque/connectip/inttest"
)

// TestGATEConnectIPMultiShortTCPBulkNoRecycleLatch is P1-4 / F3-T1:
// N short TCP + 1 bulk on one plane; siblings survive; no recycle latch.
func TestGATEConnectIPMultiShortTCPBulkNoRecycleLatch(t *testing.T) {
	inttest.RunGATEConnectIPMultiShortTCPBulkNoRecycleLatch(t)
}
