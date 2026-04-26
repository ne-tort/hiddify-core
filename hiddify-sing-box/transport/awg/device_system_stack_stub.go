//go:build !with_gvisor

package awg

import tun "github.com/sagernet/sing-tun"

func newSystemStackDevice(opt tunPickOptions) (tunAdapter, error) {
	return nil, tun.ErrGVisorNotIncluded
}
