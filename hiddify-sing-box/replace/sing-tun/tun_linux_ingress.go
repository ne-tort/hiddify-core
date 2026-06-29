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
	if !t.vnetHdr {
		t.writeAccess.Lock()
		defer t.writeAccess.Unlock()
		n, err := t.tunFile.Write(p)
		if err != nil {
			return n, err
		}
		return len(p), nil
	}
	buffer := buf.Get(virtioNetHdrLen + len(p))
	copy(buffer[virtioNetHdrLen:], p)
	_, err := t.BatchWrite([][]byte{buffer}, virtioNetHdrLen)
	buf.Put(buffer)
	if err != nil {
		return 0, err
	}
	return len(p), nil
}
