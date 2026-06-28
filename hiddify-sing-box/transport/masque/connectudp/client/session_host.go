// Package client wires CONNECT-UDP overlay dial/listen from package masque.
//
// SessionUDP is implemented by masque.connectUDPPlaneHost (see connectudp_plane_host.go)
// because the host adapter holds *coreSession and cannot live here without an import cycle.
package client
