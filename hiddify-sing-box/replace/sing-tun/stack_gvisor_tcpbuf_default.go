// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build with_gvisor && !ios

package tun

import "github.com/sagernet/gvisor/pkg/tcpip/transport/tcp"

const (
	tcpRXBufMinSize = tcp.MinBufferSize
	tcpRXBufDefSize = tcp.DefaultSendBufferSize
	tcpRXBufMaxSize = 8 << 20 // 8MiB

	tcpTXBufMinSize = tcp.MinBufferSize
	// Colo A/B txbuf 256/512KiB: CIP UP~98 flat + sndbuf_limited~11% — REJECT (2026-07-24).
	tcpTXBufDefSize = tcp.DefaultReceiveBufferSize
	tcpTXBufMaxSize = 6 << 20 // 6MiB
)
