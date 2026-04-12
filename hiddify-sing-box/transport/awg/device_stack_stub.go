//go:build !with_gvisor

package awg

import (
	"github.com/sagernet/sing-tun"
)

func newAwgStackDevice(opt tunPickOptions) (tunAdapter, error) {
	return nil, tun.ErrGVisorNotIncluded
}
