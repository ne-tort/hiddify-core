package flowcontrol

import (
	"testing"

	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/utils"

	"github.com/stretchr/testify/require"
)

func newTestStreamFC(t *testing.T) StreamFlowController {
	t.Helper()
	return NewStreamFlowController(
		42,
		NewConnectionFlowController(
			protocol.MaxByteCount,
			protocol.MaxByteCount,
			nil,
			utils.NewRTTStats(),
			utils.DefaultLogger,
		),
		100,
		100,
		protocol.MaxByteCount,
		utils.NewRTTStats(),
		utils.DefaultLogger,
	)
}

func TestMasqueFastWindowUpdatesDefault(t *testing.T) {
	t.Setenv("MASQUE_QUIC_FAST_WINDOW_UPDATES", "")
	t.Setenv("MASQUE_QUIC_WINDOW_UPDATE_THRESHOLD", "")
	t.Setenv("MASQUE_QUIC_DOWNLOAD_EAGER_WINDOW", "")

	fc := newTestStreamFC(t)
	hasUpdate, _ := fc.AddBytesRead(1)
	require.True(t, hasUpdate, "MASQUE download-eager default should update after 1 byte on 100-byte window")
}

func TestMasqueDownloadEagerWindowDisabled(t *testing.T) {
	t.Setenv("MASQUE_QUIC_DOWNLOAD_EAGER_WINDOW", "0")
	t.Setenv("MASQUE_QUIC_FAST_WINDOW_UPDATES", "1")
	t.Setenv("MASQUE_QUIC_WINDOW_UPDATE_THRESHOLD", "")

	fc := newTestStreamFC(t)
	hasUpdate, _ := fc.AddBytesRead(1)
	require.True(t, hasUpdate, "FAST_WINDOW 0.01 still updates early on 100-byte window")
}

func TestMasqueFastWindowUpdatesDisabled(t *testing.T) {
	t.Setenv("MASQUE_QUIC_DOWNLOAD_EAGER_WINDOW", "0")
	t.Setenv("MASQUE_QUIC_FAST_WINDOW_UPDATES", "0")
	t.Setenv("MASQUE_QUIC_WINDOW_UPDATE_THRESHOLD", "")

	fc := newTestStreamFC(t)
	hasUpdate, _ := fc.AddBytesRead(4)
	require.False(t, hasUpdate)
	hasUpdate, _ = fc.AddBytesRead(1)
	require.True(t, hasUpdate, "stock threshold 0.05 should update after 5 bytes on 100-byte window")
}

func TestMasqueWindowUpdateThresholdEnv(t *testing.T) {
	t.Setenv("MASQUE_QUIC_FAST_WINDOW_UPDATES", "0")
	t.Setenv("MASQUE_QUIC_WINDOW_UPDATE_THRESHOLD", "0.25")

	fc := newTestStreamFC(t)
	hasUpdate, _ := fc.AddBytesRead(24)
	require.False(t, hasUpdate)
	hasUpdate, _ = fc.AddBytesRead(1)
	require.True(t, hasUpdate, "custom threshold 0.25 should update after 25 bytes on 100-byte window")
}

func TestMasqueWindowUpdateThresholdExplicitFastOff(t *testing.T) {
	t.Setenv("MASQUE_QUIC_DOWNLOAD_EAGER_WINDOW", "0")
	t.Setenv("MASQUE_QUIC_FAST_WINDOW_UPDATES", "0")
	t.Setenv("MASQUE_QUIC_WINDOW_UPDATE_THRESHOLD", "")

	fc := newTestStreamFC(t)
	require.Zero(t, fc.GetWindowUpdate(monotime.Now()))
	hasUpdate, _ := fc.AddBytesRead(1)
	require.False(t, hasUpdate)
	require.Zero(t, fc.GetWindowUpdate(monotime.Now()))
}
