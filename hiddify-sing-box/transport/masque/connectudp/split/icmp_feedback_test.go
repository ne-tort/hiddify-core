package split

import (
	"errors"
	"net"
	"testing"

	M "github.com/sagernet/sing/common/metadata"
	"github.com/stretchr/testify/require"
)

func TestPortUnreachableErrorIs(t *testing.T) {
	err := NewPortUnreachableError(&net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 5201})
	require.ErrorIs(t, err, ErrPortUnreachable)
	var pe *PortUnreachableError
	require.True(t, errors.As(err, &pe))
	require.Equal(t, uint16(5201), pe.Remote.Port)
	require.Equal(t, "1.2.3.4", pe.Remote.Addr.String())
}

func TestPortUnreachableRemoteFallback(t *testing.T) {
	fb := M.ParseSocksaddr("203.0.113.9:53")
	require.Equal(t, fb, PortUnreachableRemote(ErrPortUnreachable, fb))
}
