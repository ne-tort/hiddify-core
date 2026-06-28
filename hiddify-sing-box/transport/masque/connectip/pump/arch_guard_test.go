package pump

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestConnectIPArchGuardTunnelDeviceContract locks W-IP-ARCH-0 Device API surface.
func TestConnectIPArchGuardTunnelDeviceContract(t *testing.T) {
	t.Parallel()
	var dev TunnelDevice = (*stubDevice)(nil)
	_ = dev
}

type stubDevice struct{}

func (stubDevice) ReadPacket(_ context.Context, _ []byte) (int, error) { return 0, nil }
func (stubDevice) WritePacket(_ []byte) error                            { return nil }
func (stubDevice) Close() error                                          { return nil }

// TestConnectIPArchGuardNativeTUNMustNotUseDialTCPInPump ensures pump layer stays wire/device only.
func TestConnectIPArchGuardNativeTUNMustNotUseDialTCPInPump(t *testing.T) {
	t.Parallel()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	root := filepath.Dir(filename)
	violations := scanGoDir(root, "dial_tcp")
	if len(violations) > 0 {
		t.Fatalf("pump/ must not reference dial_tcp:\n%s", strings.Join(violations, "\n"))
	}
}

func scanGoDir(dir, forbidden string) []string {
	var out []string
	entries, err := os.ReadDir(dir)
	if err != nil {
		return []string{err.Error()}
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		path := filepath.Join(dir, name)
		body, err := os.ReadFile(path)
		if err != nil {
			out = append(out, err.Error())
			continue
		}
		if strings.Contains(string(body), forbidden) {
			out = append(out, path)
		}
	}
	return out
}
