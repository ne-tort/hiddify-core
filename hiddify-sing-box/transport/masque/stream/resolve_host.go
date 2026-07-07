package stream

import (
	"errors"
	"strings"

	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
)

// ResolveDestinationHost maps a Socksaddr to the host string used in MASQUE TCP/UDP templates.
//
// Sing-box owns DNS: when route/dialer already resolved the destination, Addr is set alongside
// Fqdn. Prefer the literal address so MASQUE never re-resolves on client or server.
func ResolveDestinationHost(destination M.Socksaddr) (string, error) {
	if destination.Addr.IsValid() {
		host := strings.TrimSpace(destination.Addr.Unmap().String())
		if host == "" {
			return "", errors.Join(Errs.Capability, E.New("invalid destination host"))
		}
		return host, nil
	}
	// ParseSocksaddrHostPort stores the raw host string in Fqdn; leading/trailing ASCII
	// whitespace breaks net.isDomainName and made IsFqdn() false on otherwise valid names.
	fqdnTrim := strings.TrimSpace(destination.Fqdn)
	if destination.IsFqdn() {
		if fqdnTrim == "" {
			return "", errors.Join(Errs.Capability, E.New("invalid destination host"))
		}
		return fqdnTrim, nil
	}
	if fqdnTrim != "" {
		stub := M.Socksaddr{Fqdn: fqdnTrim}
		if stub.IsFqdn() {
			return fqdnTrim, nil
		}
	}
	return "", errors.Join(Errs.Capability, E.New("invalid destination"))
}
