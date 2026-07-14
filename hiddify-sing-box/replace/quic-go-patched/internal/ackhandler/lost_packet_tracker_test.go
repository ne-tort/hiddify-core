package ackhandler

import (
	"maps"
	"testing"
	"time"

	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/protocol"

	"github.com/stretchr/testify/require"
)

func TestLostPacketTracker(t *testing.T) {
	lt := newLostPacketTracker(4)

	start := monotime.Now()
	lt.Add(1, start, 100)
	lt.Add(5, start.Add(time.Second), 200)
	lt.Add(8, start.Add(2*time.Second), 300)
	require.Equal(t, map[protocol.PacketNumber]monotime.Time{
		1: start,
		5: start.Add(time.Second),
		8: start.Add(2 * time.Second),
	}, maps.Collect(lt.All()))

	// Lose 2 more packets. The first one should be removed when the tracker is full.
	lt.Add(10, start.Add(3*time.Second), 400)
	ev, ok := lt.Add(11, start.Add(4*time.Second), 500)
	require.True(t, ok)
	require.Equal(t, protocol.PacketNumber(1), ev.PacketNumber)
	require.Equal(t, protocol.ByteCount(100), ev.Length)
	require.Equal(t, map[protocol.PacketNumber]monotime.Time{
		5:  start.Add(time.Second),
		8:  start.Add(2 * time.Second),
		10: start.Add(3 * time.Second),
		11: start.Add(4 * time.Second),
	}, maps.Collect(lt.All()))

	require.Equal(t, protocol.ByteCount(200), lt.Delete(5))
	require.Equal(t, protocol.ByteCount(400), lt.Delete(10))
	require.Equal(t, protocol.ByteCount(0), lt.Delete(99))
	require.Equal(t, map[protocol.PacketNumber]monotime.Time{
		8:  start.Add(2 * time.Second),
		11: start.Add(4 * time.Second),
	}, maps.Collect(lt.All()))
}

func TestLostPacketTrackerDeleteBefore(t *testing.T) {
	lt := newLostPacketTracker(4)

	trackedPackets := func(lt *lostPacketTracker) []protocol.PacketNumber {
		var pns []protocol.PacketNumber
		for pn := range lt.All() {
			pns = append(pns, pn)
		}
		return pns
	}

	start := monotime.Now()
	lt.Add(1, start, 1)
	lt.Add(5, start.Add(time.Second), 1)
	lt.Add(8, start.Add(2*time.Second), 1)
	lt.Add(10, start.Add(3*time.Second), 1)

	require.Equal(t, []protocol.PacketNumber{1, 5, 8, 10}, trackedPackets(lt))

	lt.DeleteBefore(start) // this should be a no-op
	require.Equal(t, []protocol.PacketNumber{1, 5, 8, 10}, trackedPackets(lt))

	removed := lt.DeleteBefore(start.Add(2 * time.Second))
	require.Equal(t, []protocol.PacketNumber{1, 5}, func() []protocol.PacketNumber {
		var pns []protocol.PacketNumber
		for _, p := range removed {
			pns = append(pns, p.PacketNumber)
		}
		return pns
	}())
	require.Equal(t, []protocol.PacketNumber{8, 10}, trackedPackets(lt))

	removed = lt.DeleteBefore(start.Add(time.Second * 5 / 2))
	require.Equal(t, []protocol.PacketNumber{8}, func() []protocol.PacketNumber {
		var pns []protocol.PacketNumber
		for _, p := range removed {
			pns = append(pns, p.PacketNumber)
		}
		return pns
	}())
	require.Equal(t, []protocol.PacketNumber{10}, trackedPackets(lt))

	removed = lt.DeleteBefore(start.Add(time.Hour))
	require.Len(t, removed, 1)
	require.Equal(t, protocol.PacketNumber(10), removed[0].PacketNumber)
	require.Empty(t, trackedPackets(lt))
}
