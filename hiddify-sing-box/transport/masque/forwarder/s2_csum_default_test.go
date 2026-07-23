package forwarder

import "testing"

func TestS2VerifyInnerTCPChecksumDefaultOff(t *testing.T) {
	// OnceValue is process-wide; do not Parallel with env-mutating tests.
	if s2VerifyInnerTCPChecksum() {
		t.Fatal("default s2VerifyInnerTCPChecksum want false (skip); set MASQUE_S2_VERIFY_INNER_CSUM=1 to enable")
	}
}
