package connectip

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/stretchr/testify/require"
)

func TestIsBenignStreamTeardownError0x100(t *testing.T) {
	t.Parallel()
	err := &quic.ApplicationError{ErrorCode: 0x100, Remote: true}
	require.True(t, IsBenignStreamTeardownError(err))
	require.False(t, IsBenignStreamTeardownError(&quic.ApplicationError{ErrorCode: 0x100, Remote: false}))
	require.False(t, IsBenignStreamTeardownError(&quic.ApplicationError{ErrorCode: 0x101, Remote: true}))
	require.True(t, IsBenignStreamTeardownError(io.EOF))
	require.True(t, IsBenignStreamTeardownError(errors.New("application error 0x100 (remote)")))
}

type errReadStream struct {
	readErr error
}

func (s *errReadStream) Read([]byte) (int, error)                      { return 0, s.readErr }
func (s *errReadStream) Write([]byte) (int, error)                     { return 0, s.readErr }
func (s *errReadStream) Close() error                                  { return nil }
func (s *errReadStream) ReceiveDatagram(context.Context) ([]byte, error) {
	return nil, s.readErr
}
func (s *errReadStream) SendDatagram([]byte) error { return nil }
func (s *errReadStream) CancelRead(quic.StreamErrorCode)                 {}
func (s *errReadStream) CancelWrite(quic.StreamErrorCode)                {}
func (s *errReadStream) SetReadDeadline(time.Time) error                 { return nil }
func (s *errReadStream) SetWriteDeadline(time.Time) error                { return nil }
func (s *errReadStream) SetDeadline(time.Time) error                     { return nil }

func TestReadFromStreamBenign0x100(t *testing.T) {
	t.Parallel()
	conn := &Conn{
		str: &errReadStream{
			readErr: &quic.ApplicationError{ErrorCode: 0x100, Remote: true},
		},
		closeChan: make(chan struct{}),
	}
	err := conn.readFromStream()
	require.True(t, IsBenignStreamTeardownError(err))
}
