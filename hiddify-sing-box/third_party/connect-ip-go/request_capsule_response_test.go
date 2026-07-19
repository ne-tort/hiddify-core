package connectip

import (
	"net/http"
	"testing"

	"github.com/dunglas/httpsfv"
	"github.com/quic-go/quic-go/http3"
	"github.com/stretchr/testify/require"
)

func TestValidateResponseCapsuleProtocol(t *testing.T) {
	t.Parallel()

	t.Run("ok ?1", func(t *testing.T) {
		h := http.Header{}
		h.Set(http3.CapsuleProtocolHeader, capsuleProtocolHeaderValue)
		require.NoError(t, validateResponseCapsuleProtocol(h))
	})

	t.Run("missing", func(t *testing.T) {
		err := validateResponseCapsuleProtocol(http.Header{})
		require.Error(t, err)
		require.Contains(t, err.Error(), "missing Capsule-Protocol")
	})

	t.Run("nil header", func(t *testing.T) {
		err := validateResponseCapsuleProtocol(nil)
		require.Error(t, err)
	})

	t.Run("false", func(t *testing.T) {
		v, err := httpsfv.Marshal(httpsfv.NewItem(false))
		require.NoError(t, err)
		h := http.Header{}
		h.Set(http3.CapsuleProtocolHeader, v)
		err = validateResponseCapsuleProtocol(h)
		require.Error(t, err)
		require.Contains(t, err.Error(), "incorrect capsule header value")
	})
}
