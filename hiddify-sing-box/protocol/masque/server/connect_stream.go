package server

import (
	"net/http"

	cstrm "github.com/sagernet/sing-box/protocol/masque/server/connectstream"
	"github.com/yosida95/uritemplate/v3"
)

// TCPConnectHost carries CONNECT-stream handler dependencies from the parent endpoint.
type TCPConnectHost = cstrm.Host

var defaultConnectStreamHandler = cstrm.Handler{
	Hooks: cstrm.Hooks{
		ResolveTCPTarget:       ResolveTCPTargetForDial,
		ResolveTCPTargetAddrs:  ResolveTCPTargetAddrsForDial,
		AllowTCPPort:           AllowTCPPort,
		OnwardTCPDialAddr:      OnwardTCPDialAddr,
		DialTCPTargetSerial:    DialTCPTargetSerial,
		ResolveErrorHTTPStatus: ConnectStreamResolveHTTPStatus,
	},
}

// HandleTCPConnectRequest serves Extended CONNECT (connect-tcp) over the TCP path template.
func HandleTCPConnectRequest(host TCPConnectHost, w http.ResponseWriter, r *http.Request, tcpTemplate *uritemplate.Template, relaxedTCPAuthority bool) {
	defaultConnectStreamHandler.HandleConnectStream(host, w, r, tcpTemplate, relaxedTCPAuthority)
}

// ParseTCPTargetFromRequest extracts target host/port from a CONNECT request URI (path-only).
func ParseTCPTargetFromRequest(r *http.Request, template *uritemplate.Template, obfuscation bool) (string, string, error) {
	return cstrm.ParseTCPTargetFromRequest(r, template, obfuscation)
}
