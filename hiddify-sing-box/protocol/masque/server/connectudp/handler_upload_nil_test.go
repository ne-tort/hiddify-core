package connectudp

import (
	"testing"
)

// TestCloseH2OnwardConnNilSafe guards Q3: upload leg has no onward UDP conn on error paths.
func TestCloseH2OnwardConnNilSafe(t *testing.T) {
	t.Parallel()
	closeH2OnwardConn(nil)
}
