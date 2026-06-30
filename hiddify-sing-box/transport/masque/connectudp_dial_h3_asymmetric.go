package masque

import (
	"context"
	"fmt"
	"net"

	qmasque "github.com/quic-go/masque-go"
	cudpasym "github.com/sagernet/sing-box/transport/masque/connectudp/asym"
	cudph2leg "github.com/sagernet/sing-box/transport/masque/connectudp/h2"
	"github.com/yosida95/uritemplate/v3"
)

// dialConnectUDPH3Asymmetric opens download-primary + upload-only legs on one QUIC session (UDP-5p2b).
func dialConnectUDPH3Asymmetric(ctx context.Context, client *qmasque.Client, template *uritemplate.Template, target string) (net.PacketConn, error) {
	if client == nil {
		return nil, fmt.Errorf("masque h3 asymmetric: nil client")
	}
	if template == nil {
		return nil, fmt.Errorf("masque h3 asymmetric: nil template")
	}
	muxKey, err := cudpasym.NewMuxSessionKey()
	if err != nil {
		return nil, fmt.Errorf("masque h3 asymmetric mux key: %w", err)
	}
	download, _, err := client.DialAddrLeg(ctx, template, target, cudpasym.StreamRoleDownload, muxKey)
	if err != nil {
		return nil, err
	}
	local := download.LocalAddr()
	remote := local
	if ra, ok := download.(interface{ RemoteAddr() net.Addr }); ok && ra.RemoteAddr() != nil {
		remote = ra.RemoteAddr()
	}
	upload, _, err := client.DialAddrLeg(ctx, template, target, cudpasym.StreamRoleUpload, muxKey)
	if err != nil {
		_ = download.Close()
		return nil, err
	}
	return cudph2leg.NewAsymmetricPacketConn(download, []net.PacketConn{upload}, local, remote, nil), nil
}
