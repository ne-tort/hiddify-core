package quic

import (
	"context"
	_ "embed"
	"strings"
	"testing"

	"github.com/quic-go/quic-go/internal/flowcontrol"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/utils"
	"github.com/quic-go/quic-go/internal/wire"

	"go.uber.org/mock/gomock"
)

//go:embed datagram_queue.go
var datagramQueueProdSource string

//go:embed masque_wake.go
var masqueWakeProdSource string

var bidiSymbolsForbiddenInDatagramQueue = []string{
	"MasqueWakeBidi",
	"BidiDuplex",
	"MasqueDuplex",
	"MasqueIsBidi",
}

var m9ConnSendHookMarkers = []string{
	"MasqueWakeConnSend",
	"MasqueWakeConnSendDatagramCoalesced",
}

var ms3StreamWakeMarkers = []string{
	"MasqueWakeBidiDuplex",
	"MasqueWakeStreamSend",
}

func masqueWakeFuncBody(t *testing.T, name string) string {
	t.Helper()
	needle := "func " + name + "("
	idx := strings.Index(masqueWakeProdSource, needle)
	if idx < 0 {
		t.Fatalf("masque_wake.go must define %s", name)
	}
	rest := masqueWakeProdSource[idx+len(needle):]
	end := strings.Index(rest, "\nfunc ")
	if end < 0 {
		return masqueWakeProdSource[idx:]
	}
	return masqueWakeProdSource[idx : idx+len(needle)+end]
}

// TestDatagramQueueNoBidiHooks locks X-14 / G10: M9 recv/send ring has no M-S3 stream wake symbols.
func TestDatagramQueueNoBidiHooks(t *testing.T) {
	t.Parallel()
	for _, sym := range bidiSymbolsForbiddenInDatagramQueue {
		if strings.Contains(datagramQueueProdSource, sym) {
			t.Fatalf("datagram_queue.go must not reference %q (M-S3 surface)", sym)
		}
	}
}

// TestMasqueWakeFileTagsM9AndMs3Hooks documents mixed masque_wake.go until W-X-14 physical split.
func TestMasqueWakeFileTagsM9AndMs3Hooks(t *testing.T) {
	t.Parallel()
	for _, sym := range m9ConnSendHookMarkers {
		if !strings.Contains(masqueWakeProdSource, sym) {
			t.Fatalf("masque_wake.go must define M9 conn hook %q", sym)
		}
	}
	for _, sym := range ms3StreamWakeMarkers {
		if !strings.Contains(masqueWakeProdSource, sym) {
			t.Fatalf("masque_wake.go must define M-S3 stream hook %q", sym)
		}
	}
}

// TestMasqueWakeConnSendNotGatedByBidiConnWake locks P-UDP/CONNECT-IP M9 conn wake independent of M-S3 bidi duplex gate.
func TestMasqueWakeConnSendNotGatedByBidiConnWake(t *testing.T) {
	var connWakes int
	restore := SetMasqueWakeConnSendHook(func() { connWakes++ })
	defer restore()

	c := &Conn{sendingScheduled: make(chan struct{}, 1)}
	MasqueWakeConnSend(c)
	if connWakes != 1 {
		t.Fatalf("MasqueWakeConnSend hook calls=%d want 1", connWakes)
	}

	body := masqueWakeFuncBody(t, "MasqueWakeConnSend")
	if strings.Contains(body, "masqueWakeBidiConnOnReceiveRead") {
		t.Fatal("MasqueWakeConnSend must not consult MASQUE_QUIC_BIDI_CONN_WAKE gate")
	}
}

// TestMasqueWakeConnSendDatagramCoalescedNotGatedByBidiConnWake locks M9 batched DATAGRAM wake path.
func TestMasqueWakeConnSendDatagramCoalescedNotGatedByBidiConnWake(t *testing.T) {
	var connWakes int
	restore := SetMasqueWakeConnSendHook(func() { connWakes++ })
	defer restore()

	c := &Conn{
		sendingScheduled: make(chan struct{}, 1),
		config:           &Config{EnableDatagrams: true},
		datagramQueue:    newDatagramQueue(func() {}, utils.DefaultLogger),
	}
	frame := &wire.DatagramFrame{DataLenPresent: true, Data: []byte{0x01}}
	if err := c.datagramQueue.AddNoWake(frame); err != nil {
		t.Fatal(err)
	}

	MasqueWakeConnSendDatagramCoalesced(c)
	if connWakes != 1 {
		t.Fatalf("MasqueWakeConnSendDatagramCoalesced hook calls=%d want 1", connWakes)
	}

	body := masqueWakeFuncBody(t, "MasqueWakeConnSendDatagramCoalesced")
	if strings.Contains(body, "masqueWakeBidiConnOnReceiveRead") {
		t.Fatal("MasqueWakeConnSendDatagramCoalesced must not consult MASQUE_QUIC_BIDI_CONN_WAKE gate")
	}
}

// TestMasqueWakeBidiDuplexConnWakeAlwaysOn locks M-S3 conn half always scheduled with stream wake (prod hardcoded on).
func TestMasqueWakeBidiDuplexConnWakeAlwaysOn(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockSender := NewMockStreamSender(ctrl)
	mockSender.EXPECT().onHasConnectionData().Times(1)

	var streamWakes, connWakes int
	restoreStream := SetMasqueWakeStreamSendHook(func() { streamWakes++ })
	defer restoreStream()
	restoreConn := SetMasqueWakeConnSendHook(func() { connWakes++ })
	defer restoreConn()

	ctx := context.Background()
	connFC := flowcontrol.NewConnectionFlowController(
		protocol.DefaultInitialMaxData,
		protocol.DefaultMaxReceiveConnectionFlowControlWindow,
		nil,
		utils.NewRTTStats(),
		utils.DefaultLogger,
	)
	fc := flowcontrol.NewStreamFlowController(
		4, connFC,
		protocol.DefaultInitialMaxStreamData,
		protocol.DefaultMaxReceiveStreamFlowControlWindow,
		protocol.DefaultInitialMaxStreamData,
		utils.NewRTTStats(),
		utils.DefaultLogger,
	)
	st := newStream(ctx, 4, mockSender, fc, false)

	MasqueWakeBidiDuplex(st)
	if streamWakes != 1 {
		t.Fatalf("stream hook calls=%d want 1", streamWakes)
	}
	if connWakes != 1 {
		t.Fatalf("conn hook calls=%d want 1 (prod always-on bidi conn wake)", connWakes)
	}
}
