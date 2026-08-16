package hcore

import (
	"context"
	"net"

	hcommon "github.com/ne-tort/pathology-core/v2/hcommon"
)

func (s *CoreService) GetLANIP(ctx context.Context, empty *hcommon.Empty) (*LANIPResponse, error) {
	_ = ctx
	_ = empty
	ip := primaryLANIPv4()
	return &LANIPResponse{Ip: ip}, nil
}

func primaryLANIPv4() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil || ip.IsLoopback() {
				continue
			}
			ip = ip.To4()
			if ip == nil {
				continue
			}
			return ip.String()
		}
	}
	return ""
}
