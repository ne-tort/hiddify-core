//go:build with_gvisor && linux

package tun

import (
	"log"
	"os"
	"strings"
	"sync/atomic"
)

var hostEgressRawReadCount atomic.Uint64

func hostEgressTraceEnabled() bool {
	return strings.TrimSpace(os.Getenv("HIDDIFY_MASQUE_CONNECT_IP_TUN_EGRESS_TRACE")) == "1"
}

func logHostEgressRawRead(n int, err error, b0, b10 byte, vnet bool) {
	if !hostEgressTraceEnabled() {
		return
	}
	c := hostEgressRawReadCount.Add(1)
	if c <= 64 || (c%1000 == 0 && n > 0) {
		log.Printf("connect-ip tun raw read #%d vnet=%v n=%d err=%v b0=%#x b10=%#x", c, vnet, n, err, b0, b10)
	}
}
