package h2

import (
	"bytes"
	"sync"
	"testing"

	h2c "github.com/sagernet/sing-box/transport/masque/h2"
)

// TestTakeUploadPendingLockedDetachesBuffer covers AUDIT A2 / TASKS F1.1:
// take must not leave flush wire aliased with uploadPending after Unlock.
func TestTakeUploadPendingLockedDetachesBuffer(t *testing.T) {
	c := &PacketConn{}
	h2c.AppendDatagramCapsuleBuffer(&c.uploadPending, []byte("hello-payload"))
	wire := c.takeUploadPendingLocked()
	if len(wire) == 0 {
		t.Fatal("empty wire")
	}
	orig := append([]byte(nil), wire...)
	c.uploadPending.Write(bytes.Repeat([]byte{0xff}, len(wire)+64))
	if !bytes.Equal(wire, orig) {
		t.Fatal("wire aliased with uploadPending after take — flush would see corruption")
	}
}

func TestTakeUploadPendingLockedConcurrentFlushSafe(t *testing.T) {
	c := &PacketConn{}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 200; i++ {
			c.writeMu.Lock()
			h2c.AppendDatagramCapsuleBuffer(&c.uploadPending, []byte{byte(i), 'a', 'b', 'c'})
			wire := c.takeUploadPendingLocked()
			c.writeMu.Unlock()
			sum := 0
			for _, b := range wire {
				sum += int(b)
			}
			_ = sum
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 200; i++ {
			c.FlushC2SWrites()
		}
	}()
	wg.Wait()
}
