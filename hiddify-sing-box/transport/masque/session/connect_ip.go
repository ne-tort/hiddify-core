// Package session CONNECT-IP plane lifecycle (W-IP-ARCH-3).
//
// OpenIPSessionLocked, CloseConnectIPDataplaneLockedAssumeMu, and CoreSession IP fields
// live in the session implementation consumed by connectip_plane_host.
//
// Recycle signals: coreSession.MarkConnectIPServerRecycled / ClearConnectIPServerRecycled
// in transport/masque/connectip_session_lifecycle.go.
package session
