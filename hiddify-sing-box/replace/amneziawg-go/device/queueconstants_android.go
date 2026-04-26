/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

import "github.com/amnezia-vpn/amneziawg-go/conn"

/* Reduce memory consumption for Android */

const (
	QueueStagedSize    = conn.IdealBatchSize
	QueueOutboundSize  = 1024
	QueueInboundSize   = 1024
	QueueHandshakeSize = 1024
	// Keep Android behavior aligned with wireguard-go to cap per-packet memory pressure.
	MaxSegmentSize             = 2200
	PreallocatedBuffersPerPool = 4096
)
