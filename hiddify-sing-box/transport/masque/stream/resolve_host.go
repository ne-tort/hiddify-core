package stream

import (
	"errors"
	"strings"

	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
)

// ResolveDestinationHost maps a Socksaddr to the host string used in MASQUE TCP/UDP templates.
func ResolveDestinationHost(destination M.Socksaddr) (string, error) {
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
		if stub.IsFqdn() && !destination.Addr.IsValid() {
			return fqdnTrim, nil
		}
	}
	if destination.Addr.IsValid() {
		host := strings.TrimSpace(destination.Addr.String())
		if host == "" {
			return "", errors.Join(Errs.Capability, E.New("invalid destination host"))
		}
		return host, nil
	}
	return "", errors.Join(Errs.Capability, E.New("invalid destination"))
}
