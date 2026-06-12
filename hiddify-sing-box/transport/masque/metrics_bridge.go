package masque

import "github.com/sagernet/sing-box/transport/masque/session"

type MetricsSnapshot = session.MetricsSnapshot

func SnapshotMetrics() MetricsSnapshot {
	return session.SnapshotMetrics()
}
