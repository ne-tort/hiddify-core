// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build with_gvisor && !ios

package tun

import "github.com/sagernet/gvisor/pkg/tcpip/transport/tcp"

const (
	tcpRXBufMinSize = tcp.MinBufferSize
	tcpRXBufDefSize = tcp.DefaultSendBufferSize
	tcpRXBufMaxSize = 16 << 20 // align with tunGvisorTCPBulkBuf / MASQUE relay

	tcpTXBufMinSize = tcp.MinBufferSize
	tcpTXBufDefSize = tcp.DefaultReceiveBufferSize
	tcpTXBufMaxSize = 16 << 20 // align with tunGvisorTCPBulkBuf / MASQUE relay
)
