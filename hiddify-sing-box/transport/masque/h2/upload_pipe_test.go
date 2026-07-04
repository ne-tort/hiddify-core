package h2

import "testing"

func TestConnectStreamUploadShallowPipeProdDefault(t *testing.T) {
	r, w := NewConnectUploadPipe()
	capFn, ok := r.(interface{ UploadPipeCap() int })
	if !ok {
		t.Fatal("upload pipe reader must implement UploadPipeCap")
	}
	if cap := capFn.UploadPipeCap(); cap != ExportConnectUploadShallowPipeBuf() {
		t.Fatalf("prod pipe cap=%d want=%d", cap, ExportConnectUploadShallowPipeBuf())
	}
	_ = w.Close()
	_ = r.Close()
}
