package http3

import (
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/testutils/events"

	"github.com/stretchr/testify/require"
)

func TestMasqueWakeSendOnReceiveReadProdDefault(t *testing.T) {
	if !masqueWakeSendOnReceiveRead() {
		t.Fatal("MASQUE_QUIC_WAKE_SEND_ON_RECEIVE_READ: prod default is enabled when unset")
	}
}

func TestMasqueWakeOncePerStreamRead(t *testing.T) {
	t.Setenv("MASQUE_QUIC_WAKE_SEND_ON_RECEIVE_READ", "1")

	var wakes int
	restore := quic.SetMasqueWakeStreamSendHook(func() { wakes++ })
	defer restore()

	clientStr, serverStr := newStreamPair(t)
	clientStr.SetReadDeadline(time.Time{})
	sts := newStateTrackingStream(clientStr, nil, func([]byte) error { return nil }, nil)

	var eventRecorder events.Recorder
	clientConn, _ := newConnPair(t, withClientRecorder(&eventRecorder))
	str := newStream(
		sts,
		newRawConn(clientConn, false, nil, nil, &eventRecorder, nil),
		nil,
		func(r io.Reader, hf *headersFrame) error { return nil },
		&eventRecorder,
	)

	_, err := serverStr.Write(getDataFrame([]byte("foobar")))
	require.NoError(t, err)

	b := make([]byte, 6)
	n, err := str.Read(b)
	require.NoError(t, err)
	require.Equal(t, 6, n)
	require.Equal(t, 0, wakes, "Stream.Read must not wake on download-only — WriteTo batches delivery wake")

	wakes = 0
	_, err = serverStr.Write(getDataFrame([]byte("quux")))
	require.NoError(t, err)
	rb := newResponseBody(str, -1, make(chan struct{}))
	n, err = rb.Read(b[:4])
	require.NoError(t, err)
	require.Equal(t, 4, n)
	require.Equal(t, 0, wakes, "hijackableBody.Read must not wake on small download-only reads")
}

func TestMasqueWakeBidiConnWakeUsesDuplex(t *testing.T) {
	t.Setenv("MASQUE_QUIC_WAKE_SEND_ON_RECEIVE_READ", "1")

	var streamWakes, connWakes int
	restoreStream := quic.SetMasqueWakeStreamSendHook(func() { streamWakes++ })
	defer restoreStream()
	restoreConn := quic.SetMasqueWakeConnSendHook(func() { connWakes++ })
	defer restoreConn()

	clientStr, serverStr := newStreamPair(t)
	clientStr.SetReadDeadline(time.Time{})
	sts := newStateTrackingStream(clientStr, nil, func([]byte) error { return nil }, nil)

	var eventRecorder events.Recorder
	clientConn, _ := newConnPair(t, withClientRecorder(&eventRecorder))
	str := newStream(
		sts,
		newRawConn(clientConn, false, nil, nil, &eventRecorder, nil),
		nil,
		func(r io.Reader, hf *headersFrame) error { return nil },
		&eventRecorder,
	)

	_, err := serverStr.Write(getDataFrame([]byte("foobar")))
	require.NoError(t, err)

	b := make([]byte, 6)
	n, err := str.Read(b)
	require.NoError(t, err)
	require.Equal(t, 6, n)
	require.Equal(t, 0, streamWakes, "download-only Read must not wake before duplex upload starts")
	require.Equal(t, 0, connWakes, "download-only Read must not conn-wake before duplex upload starts")
}

func TestMasqueWakeAfterDownloadWriteOnActiveStream(t *testing.T) {
	t.Setenv("MASQUE_QUIC_WAKE_SEND_ON_RECEIVE_READ", "1")

	var streamWakes, connWakes int
	restoreStream := quic.SetMasqueWakeStreamSendHook(func() { streamWakes++ })
	defer restoreStream()
	restoreConn := quic.SetMasqueWakeConnSendHook(func() { connWakes++ })
	defer restoreConn()

	_, serverStr := newStreamPair(t)
	quic.MasqueSetBidiDownloadActive(serverStr, true)
	defer quic.MasqueSetBidiDownloadActive(serverStr, false)
	streamWakes, connWakes = 0, 0 // activation wake tested separately

	sts := newStateTrackingStream(serverStr, nil, func([]byte) error { return nil }, nil)
	var eventRecorder events.Recorder
	serverConn, _ := newConnPair(t, withClientRecorder(&eventRecorder))
	str := newStream(
		sts,
		newRawConn(serverConn, false, nil, nil, &eventRecorder, nil),
		nil,
		func(r io.Reader, hf *headersFrame) error { return nil },
		&eventRecorder,
	)

	n, err := str.Write([]byte("payload"))
	require.NoError(t, err)
	require.Equal(t, 7, n)
	// Frame + payload each poke eager MAX_STREAM_DATA → first-control-frame wake + delivery wake (REF1-2).
	require.Equal(t, 4, streamWakes, "download-active Stream.Write: quic chunk + eager poke wake per half")
	require.Equal(t, 4, connWakes, "download-active Stream.Write: bidi conn wake per quic chunk + poke")

	streamWakes, connWakes = 0, 0
	quic.MasqueSetBidiDownloadActive(serverStr, false)
	n, err = str.Write([]byte("idle"))
	require.NoError(t, err)
	require.Equal(t, 4, n)
	require.Equal(t, 2, streamWakes, "upload-only Stream.Write must wake send per quic chunk (no eager poke)")
	require.Equal(t, 2, connWakes, "upload-only Stream.Write must wake conn send per quic chunk")
}

func TestMasqueSetBidiDownloadActiveEagerActivationWake(t *testing.T) {
	t.Setenv("MASQUE_QUIC_WAKE_SEND_ON_RECEIVE_READ", "1")
	t.Setenv("MASQUE_QUIC_DOWNLOAD_EAGER_WINDOW", "1")

	var streamWakes int
	restore := quic.SetMasqueWakeStreamSendHook(func() { streamWakes++ })
	defer restore()

	_, serverStr := newStreamPair(t)
	quic.MasqueSetBidiDownloadActive(serverStr, true)
	require.Equal(t, 1, streamWakes, "eager download-active must MasqueWakeStreamSend on activation")

	streamWakes = 0
	quic.MasqueSetBidiDownloadActive(serverStr, false)
	require.Equal(t, 0, streamWakes, "deactivate must not wake")
}

func TestConnectRequestBodyCopySizeEnv(t *testing.T) {
	t.Setenv("MASQUE_H3_CONNECT_UPLOAD_CHUNK", "8")
	t.Setenv("MASQUE_H2_CONNECT_UPLOAD_CHUNK", "")
	if got := sendRequestBodyCopySize(http.MethodConnect); got != 8*1024 {
		t.Fatalf("H3 env chunk = %d, want %d", got, 8*1024)
	}

	t.Setenv("MASQUE_H3_CONNECT_UPLOAD_CHUNK", "")
	t.Setenv("MASQUE_H2_CONNECT_UPLOAD_CHUNK", "16")
	if got := sendRequestBodyCopySize(http.MethodConnect); got != 16*1024 {
		t.Fatalf("H2 fallback chunk = %d, want %d", got, 16*1024)
	}

	t.Setenv("MASQUE_H3_CONNECT_UPLOAD_CHUNK", "")
	t.Setenv("MASQUE_H2_CONNECT_UPLOAD_CHUNK", "")
	if got := sendRequestBodyCopySize(http.MethodConnect); got != connectRequestBodyCopySizeDefault {
		t.Fatalf("default chunk = %d, want %d", got, connectRequestBodyCopySizeDefault)
	}
	if got := sendRequestBodyCopySize(http.MethodPost); got != bodyCopyBufferSize {
		t.Fatalf("non-CONNECT must use bodyCopyBufferSize, got %d", got)
	}
}
