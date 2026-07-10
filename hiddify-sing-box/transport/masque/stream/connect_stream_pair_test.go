package stream

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	connectip "github.com/quic-go/connect-ip-go"
)

func TestAcquireDualLegOnwardSharesOneTCP(t *testing.T) {
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer echoLn.Close()
	go func() {
		for {
			c, err := echoLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}(c)
		}
	}()
	target := echoLn.Addr().String()
	pairID := NewConnectStreamPairID()
	ctx := context.Background()
	dial := func(context.Context) (net.Conn, error) {
		return net.DialTimeout("tcp", target, 2*time.Second)
	}
	dlConn, releaseDL, err := AcquireDualLegOnward(ctx, ConnectStreamLegDownload, pairID, dial)
	if err != nil {
		t.Fatalf("download leg: %v", err)
	}
	defer releaseDL()
	ulConn, releaseUL, err := AcquireDualLegOnward(ctx, ConnectStreamLegUpload, pairID, dial)
	if err != nil {
		t.Fatalf("upload leg: %v", err)
	}
	defer releaseUL()
	if dlConn.LocalAddr().String() != ulConn.LocalAddr().String() {
		t.Fatalf("expected shared onward TCP, got dl=%s ul=%s", dlConn.LocalAddr(), ulConn.LocalAddr())
	}
	if dlConn != ulConn {
		t.Fatal("expected same onward TCP conn pointer for both legs")
	}
	if _, err := ulConn.Write([]byte("ping")); err != nil {
		t.Fatalf("upload write: %v", err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(dlConn, buf); err != nil {
		t.Fatalf("download read: %v", err)
	}
	if string(buf) != "ping" {
		t.Fatalf("echo=%q want ping", string(buf))
	}
}

func TestConnectStreamPairSurvivesH2RequestContext(t *testing.T) {
	parent := ContextWithConnectStreamPair(context.Background(), "pair-abc")
	reqCtx, stop := connectip.NewH2ExtendedConnectRequestContext(parent)
	defer stop(true)
	legCtx := ContextWithConnectStreamLeg(reqCtx, ConnectStreamLegUpload)
	if got := ConnectStreamPairFromContext(legCtx); got != "pair-abc" {
		t.Fatalf("pair lost through request context: %q", got)
	}
}

func TestAcquireDualLegOnwardUploadWithoutDownloadFails(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, _, err := AcquireDualLegOnward(ctx, ConnectStreamLegUpload, "missing-pair", func(context.Context) (net.Conn, error) {
		t.Fatal("upload leg must not dial when pair is missing")
		return nil, nil
	})
	if err == nil {
		t.Fatal("expected pair-not-ready error")
	}
}
