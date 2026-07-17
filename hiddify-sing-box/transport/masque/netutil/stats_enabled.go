//go:build !masque_nostats

package netutil

// masqueStatsEnabled gates Track/Snapshot/file-dump for H2 TCP underlay.
// Build with -tags masque_nostats to strip collection (no-ops).
const masqueStatsEnabled = true
