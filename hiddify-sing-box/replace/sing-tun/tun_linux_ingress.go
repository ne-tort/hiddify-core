//go:build linux

package tun

import (
	"github.com/sagernet/sing/common/buf"
)

// WriteIngress delivers one inbound IP datagram to the host network stack (virtio hdr when vnetHdr).
// usque WaterAdapter.WritePacket parity: single write, error propagates to pump (fatal on LoopOut).
func (t *NativeTun) WriteIngress(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	return t.writeIngressLocked(p)
}

func (t *NativeTun) writeIngressLocked(p []byte) (int, error) {
	t.writeAccess.Lock()
	defer t.writeAccess.Unlock()
	if t.vnetHdr {
		buffer := buf.Get(virtioNetHdrLen + len(p))
		copy(buffer[virtioNetHdrLen:], p)
		hdr := virtioNetHdr{}
		if err := hdr.encode(buffer[:virtioNetHdrLen]); err != nil {
			buf.Put(buffer)
			return 0, err
		}
		_, err := t.tunFile.Write(buffer)
		buf.Put(buffer)
		if err != nil {
			return 0, err
		}
		return len(p), nil
	}
	n, err := t.tunFile.Write(p)
	if err != nil {
		return n, err
	}
	return len(p), nil
}
