package l3routerendpoint

import (
	"context"
	"testing"

	rt "github.com/sagernet/sing-box/common/l3router"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/buf"
	N "github.com/sagernet/sing/common/network"
)

func BenchmarkEndpointSessionConnParallel(b *testing.B) {
	session := rt.SessionKey("owner-a")
	e := &Endpoint{
		sessions: map[rt.SessionKey]N.PacketConn{
			session: nil,
		},
	}
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_ = e.sessionConn(session)
		}
	})
}

func BenchmarkEndpointEnqueueEgressQueueHitParallel(b *testing.B) {
	loggerFactory := log.NewNOPFactory()
	ep, err := NewEndpoint(context.Background(), nil, loggerFactory.Logger(), "bench", option.L3RouterEndpointOptions{
		OverflowPolicy: "drop_oldest",
	})
	if err != nil {
		b.Fatalf("NewEndpoint: %v", err)
	}
	e := ep.(*Endpoint)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			payload := buf.As([]byte{0x45, 0x00, 0x00, 0x14})
			queued, _ := e.enqueueEgress("owner-a", payload)
			if !queued {
				payload.Release()
			}
		}
	})
	b.StopTimer()
	if e.scheduler != nil {
		e.scheduler.reset(false)
	}
}
