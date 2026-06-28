package masque

import (
	"net"
	"testing"

	N "github.com/sagernet/sing/common/network"
)

func TestCMLazyHandshakeConnReportSuccess(t *testing.T) {
	lazy, app := newCMLazyHandshakeConn()
	inbound := wrapCMLazyForCM(lazy)
	remote, remoteApp := net.Pipe()
	defer remoteApp.Close()

	if err := N.ReportConnHandshakeSuccess(inbound, remote); err != nil {
		t.Fatalf("ReportConnHandshakeSuccess: %v", err)
	}
	if _, err := app.Write([]byte("hi")); err != nil {
		t.Fatalf("app write: %v", err)
	}
	buf := make([]byte, 2)
	if n, err := lazy.Read(buf); err != nil || n != 2 || string(buf) != "hi" {
		t.Fatalf("lazy read: n=%d buf=%q err=%v", n, buf, err)
	}
}
