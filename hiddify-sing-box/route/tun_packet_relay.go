package route

import (
	"sync"

	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// tunUploadPendingCap covers masque ListenPacket setup while tun ingress is already bursting.
// sing udpnat2 packetChan is only 64 slots with tail-drop; bypass it via SetHandler relay.
const tunUploadPendingCap = 8192

// tunUploadFlushInterval is tighter than SOCKS relay — gvisor calls NewPacketEx synchronously.
const tunUploadFlushInterval = 8

type pendingTunPacket struct {
	buffer      *buf.Buffer
	destination M.Socksaddr
}

// tunPacketUploadRelay forwards TUN udpnat ingress directly to masque/outbound, with C2S flush.
// Registered before slow ListenPacket to avoid udpnat 64-slot silent drops.
type tunPacketUploadRelay struct {
	mu         sync.Mutex
	dest       N.PacketWriter
	pending    []pendingTunPacket
	sinceFlush int
}

func (r *tunPacketUploadRelay) attach(dest N.PacketWriter) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.dest = dest
	for _, p := range r.pending {
		r.forwardLocked(p.buffer, p.destination)
	}
	r.pending = nil
	flushC2SWritesChain(dest)
}

func (r *tunPacketUploadRelay) NewPacketEx(buffer *buf.Buffer, destination M.Socksaddr) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.dest == nil {
		if len(r.pending) >= tunUploadPendingCap {
			buffer.Release()
			return
		}
		r.pending = append(r.pending, pendingTunPacket{buffer: buffer, destination: destination})
		return
	}
	r.forwardLocked(buffer, destination)
}

func (r *tunPacketUploadRelay) forwardLocked(buffer *buf.Buffer, destination M.Socksaddr) {
	if err := r.dest.WritePacket(buffer, destination); err != nil {
		buffer.Release()
		return
	}
	r.sinceFlush++
	if r.sinceFlush >= tunUploadFlushInterval {
		flushC2SWritesChain(r.dest)
		r.sinceFlush = 0
	}
}

func (r *tunPacketUploadRelay) flush() {
	r.mu.Lock()
	dest := r.dest
	r.mu.Unlock()
	if dest != nil {
		flushC2SWritesChain(dest)
	}
}
