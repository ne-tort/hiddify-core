// Package client wires CONNECT-IP overlay open/dial from package masque.
//
// session.IPPlaneHost and connectip.IngressHost are implemented by masque.connectIPSessionPlaneAdapter
// (see connectip_plane_host.go) because the host adapter holds *coreSession and cannot live here
// without an import cycle.
//
// Lazy plane: coreSession.connectIPPlane() → client.Plane (ipPlaneOnce, X-03 parity udpPlaneOnce).
//
// Lifecycle: ipPlaneHost (connectip_lifecycle_host.go) implements session.ConnectIPTeardownHost /
// ConnectIPAbandonHost; coreSession.lifecycleHost delegates IP teardown here (IP-STRUCT-24).
//
// Shared wire helpers: connectip/session_host.go (WireTCPIngressDeliver).
package client
