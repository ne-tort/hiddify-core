package connectip

import (
	"context"
	"net/http"
	"testing"

	"github.com/quic-go/quic-go/http3"
	"github.com/stretchr/testify/require"
)

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

// TestConnectIPH3SettingsErrorRFC9297 locks SETTINGS H3_DATAGRAM (and Extended CONNECT) gate before dial (G6 / IP-13).
func TestConnectIPH3SettingsErrorRFC9297(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		opts    DialOptions
		ext     bool
		dgram   bool
		wantSub string
	}{
		{"strict_missing_extended", DialOptions{}, false, true, "Extended CONNECT"},
		{"strict_missing_datagrams", DialOptions{}, true, false, "datagrams"},
		{"ignore_extended_without_flag", DialOptions{}, false, true, "Extended CONNECT"},
		{"ignore_extended_ok", DialOptions{IgnoreExtendedConnect: true}, false, true, ""},
		{"both_ok", DialOptions{}, true, true, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			st := http3.Settings{
				EnableExtendedConnect: tc.ext,
				EnableDatagrams:       tc.dgram,
			}
			err := connectIPH3SettingsError(&st, tc.opts)
			if tc.wantSub == "" {
				require.NoError(t, err)
			} else {
				require.ErrorContains(t, err, tc.wantSub)
			}
		})
	}
}

func TestConnectIPH3SettingsErrorNilSettings(t *testing.T) {
	t.Parallel()
	err := connectIPH3SettingsError(nil, DialOptions{})
	require.EqualError(t, err, "connect-ip: nil HTTP/3 settings")
}

// TestH2ExtendedConnectRequestContextCancelAfterDetach ensures stop(false) cancels reqCtx after stop(true).
func TestH2ExtendedConnectRequestContextCancelAfterDetach(t *testing.T) {
	t.Parallel()
	parent, parentCancel := context.WithCancel(context.Background())
	defer parentCancel()
	reqCtx, stop := NewH2ExtendedConnectRequestContext(parent)
	stop(true)
	select {
	case <-reqCtx.Done():
		t.Fatal("reqCtx canceled before Close teardown")
	default:
	}
	stop(false)
	select {
	case <-reqCtx.Done():
	default:
		t.Fatal("reqCtx must cancel on stop(false) after detach")
	}
}
