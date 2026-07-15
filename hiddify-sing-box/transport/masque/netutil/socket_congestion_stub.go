//go:build !unix

package netutil

import "syscall"

// ApplyMasqueTCPCongestionBestEffort is a no-op outside Unix (Windows lacks TCP_CONGESTION).
func ApplyMasqueTCPCongestionBestEffort(c syscall.Conn) {
	_ = c
}
