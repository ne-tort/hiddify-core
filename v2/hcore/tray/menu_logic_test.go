package tray

import (
	"testing"

	hcore "github.com/ne-tort/pathology-core/v2/hcore"
	"github.com/stretchr/testify/require"
)

func TestConnectionMenuFor_Stopped(t *testing.T) {
	labels := localeStrings{Connect: "Connect", Disconnect: "Disconnect", Connecting: "Connecting…"}
	m := connectionMenuFor(hcore.CoreStates_STOPPED, labels)
	require.Equal(t, "Connect", m.toggleLabel)
	require.True(t, m.toggleEnabled)
	require.False(t, m.showReconnect)
}

func TestConnectionMenuFor_Started(t *testing.T) {
	labels := localeStrings{Disconnect: "Disconnect"}
	m := connectionMenuFor(hcore.CoreStates_STARTED, labels)
	require.Equal(t, "Disconnect", m.toggleLabel)
	require.True(t, m.showReconnect)
	require.True(t, m.isConnected)
}

func TestConnectionMenuFor_StartingDisabled(t *testing.T) {
	labels := localeStrings{Connecting: "Connecting…"}
	m := connectionMenuFor(hcore.CoreStates_STARTING, labels)
	require.False(t, m.toggleEnabled)
	require.Equal(t, "Connecting…", m.toggleLabel)
}
