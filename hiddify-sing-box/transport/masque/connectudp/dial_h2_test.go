package connectudp

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestWarpH2AlternateDialHostSwapsSiblingIPv4(t *testing.T) {
	require.Equal(t, "162.159.198.2", WarpH2AlternateDialHost("162.159.198.1"))
	require.Equal(t, "162.159.198.1", WarpH2AlternateDialHost("162.159.198.2"))
}

func TestWarpH2AlternateDialHostRejectsNonSiblingIPv4(t *testing.T) {
	require.Equal(t, "", WarpH2AlternateDialHost("162.159.198.3"))
	require.Equal(t, "", WarpH2AlternateDialHost("engage.cloudflareclient.com"))
	require.Equal(t, "", WarpH2AlternateDialHost("2606:4700::1111"))
}

func TestH2DialHostCandidatesCfConnectIPForcesAlternateOnly(t *testing.T) {
	got := H2DialHostCandidates("cf-connect-ip", "162.159.198.1", "162.159.198.2")
	require.Equal(t, []string{"162.159.198.2"}, got)
}

func TestH2DialHostCandidatesNonCfKeepsPrimaryThenAlternate(t *testing.T) {
	got := H2DialHostCandidates("connect-ip", "162.159.198.1", "162.159.198.2")
	require.Equal(t, []string{"162.159.198.1", "162.159.198.2"}, got)
}

func TestIsH2ExtendedConnectUnsupportedByPeer(t *testing.T) {
	require.False(t, IsH2ExtendedConnectUnsupportedByPeer(nil))
	require.False(t, IsH2ExtendedConnectUnsupportedByPeer(errString("connection reset")))
	require.True(t, IsH2ExtendedConnectUnsupportedByPeer(errString("extended connect not supported by peer")))
	require.True(t, IsH2ExtendedConnectUnsupportedByPeer(errString("missing SETTINGS enable_connect_protocol")))
}

func TestProxyStatusNextHopUDP(t *testing.T) {
	require.Nil(t, ProxyStatusNextHopUDP(nil))
	rsp := &http.Response{
		Header: http.Header{
			"Proxy-Status": {`masque; next-hop="192.0.2.1:5353"`},
		},
	}
	nh := ProxyStatusNextHopUDP(rsp)
	require.NotNil(t, nh)
	require.Equal(t, "192.0.2.1", nh.IP.String())
	require.Equal(t, 5353, nh.Port)
}

type errString string

func (e errString) Error() string { return string(e) }
