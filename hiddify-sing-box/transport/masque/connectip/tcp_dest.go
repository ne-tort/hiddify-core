package connectip

import (
	"context"
	"errors"
	"net"

	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
)

// NormalizeTCPDestination resolves FQDN destinations to an IP for CONNECT-IP TCP netstack dial.
func NormalizeTCPDestination(ctx context.Context, destination M.Socksaddr) (M.Socksaddr, error) {
	if destination.Port == 0 {
		return M.Socksaddr{}, errors.Join(Errs.Dial, E.New("missing destination port"))
	}
	out := destination
	if out.Addr.IsValid() {
		return out, nil
	}
	if out.IsFqdn() {
		ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", out.Fqdn)
		if err != nil {
			return M.Socksaddr{}, errors.Join(Errs.Dial, err)
		}
		if len(ips) == 0 {
			return M.Socksaddr{}, errors.Join(Errs.Dial, E.New("DNS returned no addresses"))
		}
		for _, ip := range ips {
			ip = ip.Unmap()
			if ip.Is4() {
				out.Addr = ip
				out.Fqdn = ""
				return out, nil
			}
		}
		out.Addr = ips[0].Unmap()
		out.Fqdn = ""
		return out, nil
	}
	return M.Socksaddr{}, errors.Join(Errs.Capability, E.New("invalid masque tcp destination"))
}
