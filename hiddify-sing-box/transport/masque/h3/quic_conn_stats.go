package h3

import "github.com/quic-go/quic-go"

// TrackQUICConn is a no-op hook retained so dial/serve call sites stay stable.
// Prod does not gate behavior on getenv; loss dumps belong in explicit bench tooling.
func TrackQUICConn(role string, conn *quic.Conn) {}

// SnapshotQUICConnStats is a no-op (compat with older bench callers).
func SnapshotQUICConnStats() {}
