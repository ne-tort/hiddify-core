package awg

import (
	"errors"
	"net/netip"
	"os"
	"runtime"
	"testing"

	awgTun "github.com/amnezia-vpn/amneziawg-go/tun"
	tun "github.com/sagernet/sing-tun"
)

type fakeTun struct {
	readN      int
	readErr    error
	writeN     int
	readCalled bool
}

func (f *fakeTun) Name() (string, error)                        { return "fake", nil }
func (f *fakeTun) Start() error                                 { return nil }
func (f *fakeTun) Close() error                                 { return nil }
func (f *fakeTun) UpdateRouteOptions(tun.Options) error         { return nil }
func (f *fakeTun) Read(p []byte) (int, error)                   { f.readCalled = true; return f.readN, f.readErr }
func (f *fakeTun) Write(p []byte) (int, error)                  { return f.writeN, nil }
func (f *fakeTun) FrontHeadroom() int                           { return 0 }
func (f *fakeTun) TXChecksumOffload() bool                      { return false }
func (f *fakeTun) BatchSize() int                               { return 0 }
func (f *fakeTun) BatchRead([][]byte, int, []int) (int, error) { return 0, nil }
func (f *fakeTun) BatchWrite([][]byte, int) (int, error)        { return 0, nil }

type fakeLinuxBatchTun struct {
	fakeTun
	batchSize           int
	batchReadN          int
	batchReadErr        error
	batchWriteN         int
	batchReadCalled     bool
	batchWriteCalled    bool
	lastBatchReadOffset int
	lastBatchWriteOff   int
}

func (f *fakeLinuxBatchTun) BatchSize() int { return f.batchSize }

func (f *fakeLinuxBatchTun) BatchRead(_ [][]byte, offset int, sizes []int) (int, error) {
	f.batchReadCalled = true
	f.lastBatchReadOffset = offset
	if len(sizes) > 0 {
		sizes[0] = 12
	}
	return f.batchReadN, f.batchReadErr
}

func (f *fakeLinuxBatchTun) BatchWrite(_ [][]byte, offset int) (int, error) {
	f.batchWriteCalled = true
	f.lastBatchWriteOff = offset
	return f.batchWriteN, nil
}

func TestSystemTun_UsesLinuxBatchPath(t *testing.T) {
	fakeBatch := &fakeLinuxBatchTun{
		batchSize:   16,
		batchReadN:  2,
		batchWriteN: 3,
	}
	tunAdapter := &systemTun{
		singtun:  fakeBatch,
		batchTun: fakeBatch,
		gso:      true,
	}
	offset := tun.PacketOffset + 8
	bufs := [][]byte{make([]byte, offset+32), make([]byte, offset+32)}
	sizes := make([]int, len(bufs))

	if got := tunAdapter.BatchSize(); got != 16 {
		t.Fatalf("expected batch size 16, got %d", got)
	}

	n, err := tunAdapter.Read(bufs, sizes, offset)
	if err != nil {
		t.Fatalf("unexpected read err: %v", err)
	}
	if n != 2 {
		t.Fatalf("expected batch read count 2, got %d", n)
	}
	if !fakeBatch.batchReadCalled {
		t.Fatal("expected BatchRead to be used")
	}
	if fakeBatch.readCalled {
		t.Fatal("did not expect single Read path")
	}
	if fakeBatch.lastBatchReadOffset != offset-tun.PacketOffset {
		t.Fatalf("unexpected batch read offset: %d", fakeBatch.lastBatchReadOffset)
	}

	wN, wErr := tunAdapter.Write(bufs, offset)
	if wErr != nil {
		t.Fatalf("unexpected write err: %v", wErr)
	}
	if wN != 3 {
		t.Fatalf("expected batch write count 3, got %d", wN)
	}
	if !fakeBatch.batchWriteCalled {
		t.Fatal("expected BatchWrite to be used")
	}
	if fakeBatch.lastBatchWriteOff != offset {
		t.Fatalf("unexpected batch write offset: %d", fakeBatch.lastBatchWriteOff)
	}
}

func TestSystemTun_FallbackReadMapsTooManySegments(t *testing.T) {
	fakeSingle := &fakeTun{
		readErr: tun.ErrTooManySegments,
	}
	tunAdapter := &systemTun{
		singtun: fakeSingle,
		inet4:   netip.Addr{},
	}
	offset := tun.PacketOffset + 4
	bufs := [][]byte{make([]byte, offset+16)}
	sizes := []int{0}

	n, err := tunAdapter.Read(bufs, sizes, offset)
	if n != 0 {
		t.Fatalf("expected count=0, got %d", n)
	}
	if !errors.Is(err, awgTun.ErrTooManySegments) {
		t.Fatalf("expected awg ErrTooManySegments, got %v", err)
	}
}

func TestAwgSystemGSOEnabled_WithEndpointFlagAndEnvOverride(t *testing.T) {
	if runtime.GOOS != "linux" {
		if awgSystemGSOEnabled(true) {
			t.Fatal("expected gso disabled on non-linux")
		}
		return
	}
	old := os.Getenv("SBOX_AWG_DISABLE_GSO")
	defer func() {
		_ = os.Setenv("SBOX_AWG_DISABLE_GSO", old)
	}()
	_ = os.Unsetenv("SBOX_AWG_DISABLE_GSO")
	if !awgSystemGSOEnabled(true) {
		t.Fatal("expected gso enabled when endpoint flag is true")
	}
	if awgSystemGSOEnabled(false) {
		t.Fatal("expected gso disabled when endpoint flag is false")
	}
	_ = os.Setenv("SBOX_AWG_DISABLE_GSO", "1")
	if awgSystemGSOEnabled(true) {
		t.Fatal("expected env override to force-disable gso")
	}
}
