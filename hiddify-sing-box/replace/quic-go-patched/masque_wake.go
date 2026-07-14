package quic

// CONNECT-UDP / CONNECT-IP datagram plane wake hooks (not used by CONNECT-stream bidi).

var masqueWakeConnSendHook func()
var masqueScheduleSendingHook func()

// SetMasqueScheduleSendingHook installs fn for tests; returns restore.
func SetMasqueScheduleSendingHook(fn func()) func() {
	prev := masqueScheduleSendingHook
	masqueScheduleSendingHook = fn
	return func() { masqueScheduleSendingHook = prev }
}

// SetMasqueWakeConnSendHook installs fn for tests; returns restore.
func SetMasqueWakeConnSendHook(fn func()) func() {
	prev := masqueWakeConnSendHook
	masqueWakeConnSendHook = fn
	return func() { masqueWakeConnSendHook = prev }
}

// MasqueWakeConnSend schedules QUIC send work after CONNECT-IP ingress reads (TCP ACK datagrams).
func MasqueWakeConnSend(c *Conn) {
	if c == nil {
		return
	}
	if masqueWakeConnSendHook != nil {
		masqueWakeConnSendHook()
	}
	c.scheduleSending()
}

// MasqueWakeConnSendDatagramCoalesced schedules send after batched proxied-IP enqueue.
func MasqueWakeConnSendDatagramCoalesced(c *Conn) {
	if c == nil {
		return
	}
	if !c.masqueDatagramWakeCoalesced.CompareAndSwap(false, true) {
		if c.config.EnableDatagrams && c.datagramSendBacklog() > 0 {
			c.scheduleSending()
		}
		return
	}
	c.scheduleSending()
	if masqueWakeConnSendHook != nil {
		masqueWakeConnSendHook()
	}
}
