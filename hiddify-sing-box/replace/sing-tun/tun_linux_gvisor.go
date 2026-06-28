//go:build with_gvisor && linux

package tun

import (
	"sync"

	"github.com/sagernet/gvisor/pkg/tcpip/link/fdbased"
	"github.com/sagernet/gvisor/pkg/tcpip/stack"
)

func init() {
	fdbased.BufConfig = []int{65535}
}

var nativeTunL3KernelRelay sync.Map // *NativeTun → struct{}

// SetL3OverlayKernelRelay disables fdbased RX GRO when host kernel TCP egress is relayed via L3OverlaySend.
// GRO holds small tail segments (iperf -R 52B after 37B) until coalesce timeout → client retransmit stall.
func (t *NativeTun) SetL3OverlayKernelRelay(enabled bool) {
	if t == nil {
		return
	}
	if enabled {
		nativeTunL3KernelRelay.Store(t, struct{}{})
		return
	}
	nativeTunL3KernelRelay.Delete(t)
}

func (t *NativeTun) l3OverlayKernelRelay() bool {
	if t == nil {
		return false
	}
	_, ok := nativeTunL3KernelRelay.Load(t)
	return ok
}

var _ GVisorTun = (*NativeTun)(nil)

func (t *NativeTun) WritePacket(pkt *stack.PacketBuffer) (int, error) {
	if pkt == nil {
		return 0, nil
	}
	var flat []byte
	for _, s := range pkt.AsSlices() {
		flat = append(flat, s...)
	}
	if len(flat) == 0 {
		return 0, nil
	}
	// Kernel L3 relay: bypass TX GRO (same as CONNECT-IP WriteIngress / usque Device.WritePacket).
	if t.l3OverlayKernelRelay() {
		return t.WriteIngress(flat)
	}
	return t.Write(flat)
}

func (t *NativeTun) NewEndpoint() (stack.LinkEndpoint, stack.NICOptions, error) {
	if t.l3OverlayKernelRelay() {
		return kernelRelayStubLink{}, stack.NICOptions{}, nil
	}
	enableGRO := !t.l3OverlayKernelRelay()
	if t.vnetHdr {
		ep, err := fdbased.New(&fdbased.Options{
			FDs:               []int{t.tunFd},
			MTU:               t.options.MTU,
			GSOMaxSize:        gsoMaxSize,
			GRO:               enableGRO,
			RXChecksumOffload: true,
			TXChecksumOffload: t.txChecksumOffload,
		})
		if err != nil {
			return nil, stack.NICOptions{}, err
		}
		return ep, stack.NICOptions{}, nil
	} else {
		ep, err := fdbased.New(&fdbased.Options{
			FDs:               []int{t.tunFd},
			MTU:               t.options.MTU,
			RXChecksumOffload: true,
			TXChecksumOffload: t.txChecksumOffload,
		})
		if err != nil {
			return nil, stack.NICOptions{}, err
		}
		return ep, stack.NICOptions{}, nil
	}
}
