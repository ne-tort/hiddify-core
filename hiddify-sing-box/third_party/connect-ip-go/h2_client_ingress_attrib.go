package connectip

import (
	"sync/atomic"
	"time"
)

// Cheap always-on H2 client ingress attribution (P6-D1). No env gates / alternate modes.
var (
	h2ClientCapsuleReadParseNs   atomic.Uint64 // parseConnectIPStreamCapsule + DATAGRAM body read
	h2ClientIngressCloneNs       atomic.Uint64 // redundant clone tax (should be 0 after P6-D1 REPLACE)
	h2ClientIngressCloneBytes    atomic.Uint64
	h2ClientIngressEnqueued      atomic.Uint64
	h2ClientIngressEnqueuedBytes atomic.Uint64
	h2ClientReadPacketDeliverNs  atomic.Uint64 // successful ReadPacket copy-out path
	h2ClientReadPacketDelivered  atomic.Uint64
)

func H2ClientCapsuleReadParseNs() uint64   { return h2ClientCapsuleReadParseNs.Load() }
func H2ClientIngressCloneNs() uint64        { return h2ClientIngressCloneNs.Load() }
func H2ClientIngressCloneBytes() uint64     { return h2ClientIngressCloneBytes.Load() }
func H2ClientIngressEnqueued() uint64       { return h2ClientIngressEnqueued.Load() }
func H2ClientIngressEnqueuedBytes() uint64  { return h2ClientIngressEnqueuedBytes.Load() }
func H2ClientReadPacketDeliverNs() uint64   { return h2ClientReadPacketDeliverNs.Load() }
func H2ClientReadPacketDelivered() uint64   { return h2ClientReadPacketDelivered.Load() }

// ResetH2ClientIngressAttrib clears client ingress counters (tests).
func ResetH2ClientIngressAttrib() {
	h2ClientCapsuleReadParseNs.Store(0)
	h2ClientIngressCloneNs.Store(0)
	h2ClientIngressCloneBytes.Store(0)
	h2ClientIngressEnqueued.Store(0)
	h2ClientIngressEnqueuedBytes.Store(0)
	h2ClientReadPacketDeliverNs.Store(0)
	h2ClientReadPacketDelivered.Store(0)
}

func recordH2ClientCapsuleReadParse(start time.Time) {
	h2ClientCapsuleReadParseNs.Add(uint64(time.Since(start).Nanoseconds()))
}

func recordH2ClientIngressEnqueue(payload []byte) {
	h2ClientIngressEnqueued.Add(1)
	h2ClientIngressEnqueuedBytes.Add(uint64(len(payload)))
}

func recordH2ClientIngressClone(payload []byte, start time.Time) {
	h2ClientIngressCloneNs.Add(uint64(time.Since(start).Nanoseconds()))
	h2ClientIngressCloneBytes.Add(uint64(len(payload)))
}

func recordH2ClientReadPacketDeliver(start time.Time) {
	h2ClientReadPacketDeliverNs.Add(uint64(time.Since(start).Nanoseconds()))
	h2ClientReadPacketDelivered.Add(1)
}
