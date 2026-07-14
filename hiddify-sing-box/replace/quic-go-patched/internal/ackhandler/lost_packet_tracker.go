package ackhandler

import (
	"iter"
	"slices"

	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/protocol"
)

type lostPacket struct {
	PacketNumber protocol.PacketNumber
	SendTime     monotime.Time
	Length       protocol.ByteCount
}

type lostPacketTracker struct {
	maxLength   int
	lostPackets []lostPacket
}

func newLostPacketTracker(maxLength int) *lostPacketTracker {
	return &lostPacketTracker{
		maxLength: maxLength,
		// Preallocate a small slice only.
		// Hopefully we won't lose many packets.
		lostPackets: make([]lostPacket, 0, 4),
	}
}

// Add records a declared-lost packet for spurious-loss detection.
// If the tracker is full, the oldest entry is evicted; the caller must undo
// connStats for evicted (see sentPacketHandler.undoDeclaredLoss).
func (t *lostPacketTracker) Add(p protocol.PacketNumber, sendTime monotime.Time, length protocol.ByteCount) (evicted lostPacket, evictedOK bool) {
	if len(t.lostPackets) == t.maxLength {
		evicted = t.lostPackets[0]
		evictedOK = true
		t.lostPackets = t.lostPackets[1:]
	}
	t.lostPackets = append(t.lostPackets, lostPacket{
		PacketNumber: p,
		SendTime:     sendTime,
		Length:       length,
	})
	return evicted, evictedOK
}

// Delete removes a packet and returns its recorded length (0 if not found).
func (t *lostPacketTracker) Delete(pn protocol.PacketNumber) protocol.ByteCount {
	var length protocol.ByteCount
	t.lostPackets = slices.DeleteFunc(t.lostPackets, func(p lostPacket) bool {
		if p.PacketNumber == pn {
			length = p.Length
			return true
		}
		return false
	})
	return length
}

func (t *lostPacketTracker) All() iter.Seq2[protocol.PacketNumber, monotime.Time] {
	return func(yield func(protocol.PacketNumber, monotime.Time) bool) {
		for _, p := range t.lostPackets {
			if !yield(p.PacketNumber, p.SendTime) {
				return
			}
		}
	}
}

// DeleteBefore removes entries older than ti. Returns removed packets so the
// caller can undo connStats (they were declared lost but never proved spurious).
func (t *lostPacketTracker) DeleteBefore(ti monotime.Time) []lostPacket {
	if len(t.lostPackets) == 0 {
		return nil
	}
	if !t.lostPackets[0].SendTime.Before(ti) {
		return nil
	}
	var idx int
	for ; idx < len(t.lostPackets); idx++ {
		if !t.lostPackets[idx].SendTime.Before(ti) {
			break
		}
	}
	removed := slices.Clone(t.lostPackets[:idx])
	t.lostPackets = slices.Delete(t.lostPackets, 0, idx)
	return removed
}
