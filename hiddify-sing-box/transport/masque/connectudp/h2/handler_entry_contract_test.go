package h2

import (
	_ "embed"
	"strings"
	"testing"
)

//go:embed handler_entry.go
var connectUDPH2HandlerEntrySource string

// TestConnectUDPH2HandlerWireContract locks H2 CONNECT-UDP server wire order (moved from protocol handler).
func TestConnectUDPH2HandlerWireContract(t *testing.T) {
	t.Parallel()
	for _, sub := range []string{
		`EnableFullDuplex()`,
		`CapsuleProtocolHeader`,
		`WriteHeader(http.StatusOK)`,
		`ServeH2FromRequest`,
		`tuneH2OnwardUDP`,
	} {
		if !strings.Contains(connectUDPH2HandlerEntrySource, sub) {
			t.Fatalf("handler_entry.go: missing %q", sub)
		}
	}
	idxDuplex := strings.Index(connectUDPH2HandlerEntrySource, "EnableFullDuplex()")
	uploadSection := connectUDPH2HandlerEntrySource
	if i := strings.Index(connectUDPH2HandlerEntrySource, "if role == StreamRoleUpload"); i >= 0 {
		uploadSection = connectUDPH2HandlerEntrySource[i:]
	}
	idxUploadHeader := strings.Index(uploadSection, "w.WriteHeader(http.StatusOK)")
	idxUploadServe := strings.Index(uploadSection, "ServeH2FromRequest(w, r, conn")
	idxDownloadHeader := strings.LastIndex(connectUDPH2HandlerEntrySource, "WriteHeader(http.StatusOK)")
	if idxDuplex < 0 || idxUploadHeader < 0 || idxUploadServe < 0 || idxDownloadHeader < 0 {
		t.Fatal("handler_entry.go: missing upload/download wire anchors")
	}
	if idxUploadHeader > idxUploadServe {
		t.Fatalf("upload wire order want WriteHeader before ServeH2; got header=%d serve=%d",
			idxUploadHeader, idxUploadServe)
	}
	if idxUploadServe > idxDownloadHeader {
		t.Fatalf("download WriteHeader must follow upload branch; got upload=%d download=%d", idxUploadServe, idxDownloadHeader)
	}
}
