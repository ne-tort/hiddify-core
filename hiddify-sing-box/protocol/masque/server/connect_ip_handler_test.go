package server

import (
	_ "embed"
	"reflect"
	"strings"
	"testing"
	"unsafe"

	connectip "github.com/quic-go/connect-ip-go"
)

//go:embed connect_ip_handler.go
var connectIPHandlerGoSource string

func TestConnectIPHandlerSourceBlocksOnRouteConnectIPBlocked(t *testing.T) {
	t.Parallel()
	if !strings.Contains(connectIPHandlerGoSource, "RouteConnectIPBlocked(") {
		t.Fatal("CONNECT-IP handler must block until RouteConnectIPBlocked returns (H2/H3 parity)")
	}
	if strings.Contains(connectIPHandlerGoSource, "go RouteConnectIPBlocked") {
		t.Fatal("CONNECT-IP handler must not spawn RouteConnectIPBlocked in background")
	}
}

func TestConnectIPProxySharedSingletonStateless(t *testing.T) {
	t.Parallel()
	var p connectip.Proxy
	if unsafe.Sizeof(p) != 0 {
		t.Fatalf("connectip.Proxy must remain stateless (zero-size); got size %d", unsafe.Sizeof(p))
	}
	if sharedConnectIPProxy == nil {
		t.Fatal("sharedConnectIPProxy must be initialized")
	}
	typ := reflect.TypeOf(connectip.Proxy{})
	if typ.NumField() != 0 {
		t.Fatalf("connectip.Proxy must have no fields; got %d", typ.NumField())
	}
}
