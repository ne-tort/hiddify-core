package relay

import (
	_ "embed"
	"strings"
	"testing"
)

//go:embed h3.go
var h3RelayProdSource string

//go:embed h3_c2s.go
var h3RelayC2SSource string

//go:embed h3_c2s_udp_writer.go
var h3RelayC2SWriterSource string

//go:embed h3_s2c.go
var h3RelayS2CSource string

//go:embed h3_tune.go
var h3RelayTuneSource string

//go:embed h2_dataplane.go
var h2RelayDataplaneSource string

//go:embed onward_udp_write_batch.go
var h3RelayOnwardBatchSource string

// TestH2DataplaneHasNoBurstSendAPI locks CUT of 512-wire burst SendBurstViews on prod relay API.
func TestH2DataplaneHasNoBurstSendAPI(t *testing.T) {
	t.Parallel()
	if strings.Contains(h2RelayDataplaneSource, "SendBurstViews") {
		t.Fatal("h2_dataplane.go must not expose SendBurstViews burst API (CUT 2026-07)")
	}
}

// TestProdRelaySourceHasNoServerS2CNoWakeBatch ensures server relay stays upstream-shaped.
func TestProdRelaySourceHasNoServerS2CNoWakeBatch(t *testing.T) {
	t.Parallel()
	combined := h3RelayProdSource + h3RelayC2SSource + h3RelayS2CSource
	for _, needle := range []string{"SendDatagramNoWake", "s2cBatchAllowed", "FlushProxiedIPDatagramSend"} {
		if strings.Contains(combined, needle) {
			t.Fatalf("prod connectudp/relay/h3*.go must not contain %q", needle)
		}
	}
}

// TestProdRelaySourceHasC2SICMPRelayOnWrite locks RFC 9298 §5 ICMP relay on onward Write refused.
func TestProdRelaySourceHasC2SICMPRelayOnWrite(t *testing.T) {
	t.Parallel()
	c2sICMP := h3RelayC2SSource + h3RelayTuneSource
	for _, needle := range []string{"c2sRelayUDPWrite", "icmpRelay"} {
		if !strings.Contains(c2sICMP, needle) {
			t.Fatalf("prod connectudp/relay C2S path must contain %q", needle)
		}
	}
}

// TestProdRelayCloseClearsClosersUnderLock locks closers=nil only under mx after refCount.Wait.
func TestProdRelayCloseClearsClosersUnderLock(t *testing.T) {
	t.Parallel()
	wait := strings.Index(h3RelayProdSource, "s.refCount.Wait()")
	if wait < 0 {
		t.Fatal("missing refCount.Wait in h3.go")
	}
	tail := h3RelayProdSource[wait:]
	nilIdx := strings.Index(tail, "s.closers = nil")
	lockIdx := strings.Index(tail, "s.mx.Lock()")
	if nilIdx < 0 || lockIdx < 0 || lockIdx > nilIdx {
		t.Fatalf("closers=nil must be assigned under mx after refCount.Wait (lock@%d nil@%d)", lockIdx, nilIdx)
	}
	if !strings.Contains(h3RelayProdSource, "if s.closers != nil") {
		t.Fatal("ProxyConnectedSocket must nil-check closers before delete")
	}
}

// TestProdRelaySourceHasNoLegacyC2SDrain ensures CUT of fork backoff/writer (reference TryReceive drain OK).
func TestProdRelaySourceHasNoLegacyC2SDrain(t *testing.T) {
	t.Parallel()
	for _, needle := range []string{
		"drainQueued",
		"transientPressureBackoff",
		"OnwardUDPWriter",
		"NewOnwardUDPWriter",
	} {
		if strings.Contains(h3RelayC2SSource, needle) {
			t.Fatalf("h3_c2s.go must not contain legacy fork %q", needle)
		}
	}
}

// TestProdRelaySourceHasC2SFlushOnEOF locks tail flush when HTTP/3 datagram stream ends.
func TestProdRelaySourceHasC2SFlushOnEOF(t *testing.T) {
	t.Parallel()
	if !strings.Contains(h3RelayC2SSource, "errors.Is(err, io.EOF)") ||
		!strings.Contains(h3RelayC2SSource, "return flushC2SBatch()") {
		t.Fatal("h3_c2s.go must flush pending C2S batch on ReceiveDatagram EOF")
	}
}

// TestProdRelaySourceHasNoAsyncC2SOnwardWorker locks masque-go sync proxyConnSend (no onwardCh decouple).
func TestProdRelaySourceHasNoAsyncC2SOnwardWorker(t *testing.T) {
	t.Parallel()
	for _, needle := range []string{"onwardCh", "h3C2SOnwardItem", "onwardFlush", "go func()"} {
		if strings.Contains(h3RelayC2SSource, needle) {
			t.Fatalf("h3_c2s.go must not use async C2S onward worker %q (UDP-REF-H3-01)", needle)
		}
	}
}

// TestProdRelaySourceHasC2STryReceiveDrain locks masque-go proxyConnSend try-drain after blocking receive.
func TestProdRelaySourceHasC2STryReceiveDrain(t *testing.T) {
	t.Parallel()
	for _, needle := range []string{"TryReceiveDatagram"} {
		if !strings.Contains(h3RelayC2SSource, needle) {
			t.Fatalf("h3_c2s.go must contain reference C2S drain %q", needle)
		}
	}
}

// TestProdRelaySourceHasC2SFlushAfterDrain locks partial batch flush after TryReceive drain (fountain prime).
func TestProdRelaySourceHasC2SFlushAfterDrain(t *testing.T) {
	t.Parallel()
	if !strings.Contains(h3RelayC2SSource, "flushC2SBatch") {
		t.Fatal("h3_c2s.go must flush partial C2S batch after HTTP/3 drain")
	}
}

// TestProdRelaySourceWakesQUICAfterC2SDrain locks quic-go MASQUE upload credit after C2S consume.
func TestProdRelaySourceWakesQUICAfterC2SDrain(t *testing.T) {
	t.Parallel()
	if !strings.Contains(h3RelayC2SSource, "wakeH3RelayAfterC2SConsume") {
		t.Fatal("h3_c2s.go must wake QUIC FC after C2S datagram drain")
	}
}

// TestProdRelaySourceHasC2SReleaseAfterUDPWrite locks C1: ReleaseMasqueDatagramReceiveBuffer after onward Write.
func TestProdRelaySourceHasC2SReleaseAfterUDPWrite(t *testing.T) {
	t.Parallel()
	c2s := h3RelayC2SSource + h3RelayC2SWriterSource
	if strings.Contains(c2s, "ParseHTTPDatagramUDP(data)\n\t\tquic.ReleaseMasqueDatagramReceiveBuffer(data)") {
		t.Fatal("h3 C2S must not ReleaseMasqueDatagramReceiveBuffer before UDP write (subsliсe UAF)")
	}
	if !strings.Contains(c2s, "writePayloadBatch") {
		t.Fatal("h3 C2S must batch onward UDP writes (masque-go proxyConnSend + linux WriteBatch)")
	}
	if !strings.Contains(h3RelayC2SSource, "ReceiveDatagram(context.Background())") {
		t.Fatal("h3_c2s.go must use ReceiveDatagram(context.Background()) like masque-go proxyConnSend")
	}
}

// TestProdRelaySourceHasH2OnwardTransientWriteRetry locks H2 bidi onward zero-loss C2S parity with H3.
func TestProdRelaySourceHasH2OnwardTransientWriteRetry(t *testing.T) {
	t.Parallel()
	combined := h2RelayDataplaneSource + h3RelayOnwardBatchSource
	if !strings.Contains(combined, "c2sRelayUDPWriteReliable") {
		t.Fatal("h2 DirectH2OnwardUplink must retry transient onward UDP via c2sRelayUDPWriteReliable (H3 parity)")
	}
	if !strings.Contains(h2RelayDataplaneSource, "queueH2OnwardUDP") {
		t.Fatal("h2 bidi onward must use queueH2OnwardUDP (h2o udp_write_core)")
	}
}

// TestProdRelaySourceHasC2STransientUDPWriteRetry locks zero-loss C2S: retry transient onward UDP (not batch abort).
func TestProdRelaySourceHasC2STransientUDPWriteRetry(t *testing.T) {
	t.Parallel()
	c2s := h3RelayC2SWriterSource + h3RelayOnwardBatchSource
	if !strings.Contains(c2s, "writePayloadBatch") {
		t.Fatal("h3 C2S must batch onward UDP writes (masque-go proxyConnSend + linux WriteBatch)")
	}
	if !strings.Contains(c2s, "c2sRelayUDPWriteReliable") {
		t.Fatal("h3 C2S onward batch must delegate to c2sRelayUDPWriteReliable")
	}
	if !strings.Contains(h3RelayTuneSource, "isTransientUDPSendError") {
		t.Fatal("relay tune must classify transient onward UDP send errors")
	}
}

// TestProdRelaySourceHasS2CTransientSendRetry locks zero-loss S2C: retry transient SendDatagram (not silent drop).
func TestProdRelaySourceHasS2CTransientSendRetry(t *testing.T) {
	t.Parallel()
	if !strings.Contains(h3RelayS2CSource, "isTransientHTTPDatagramSendError") {
		t.Fatal("h3 S2C must classify transient HTTP datagram send errors")
	}
	if !strings.Contains(h3RelayS2CSource, "wakeH3RelayAfterS2CSendPressure") {
		t.Fatal("h3 S2C must wake QUIC after transient send pressure")
	}
	if strings.Contains(h3RelayS2CSource, "s2cDropSendFail.Add(1)\n\t\t}\n\t\treturn nil") {
		t.Fatal("h3 S2C must not silent-drop transient SendDatagram (zero-loss)")
	}
}

// TestProdRelaySourceHasNoLegacyS2CBackoff ensures CUT of fork S2C transient backoff loop.
func TestProdRelaySourceHasNoLegacyS2CBackoff(t *testing.T) {
	t.Parallel()
	for _, needle := range []string{"sendBackoff", "onTransientError"} {
		if strings.Contains(h3RelayS2CSource, needle) {
			t.Fatalf("h3_s2c.go must not contain legacy fork %q (upstream masque-go)", needle)
		}
	}
}
