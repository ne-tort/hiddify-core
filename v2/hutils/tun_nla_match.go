package hutils

import "strings"

// nlaNamePrefixes match NLA ProfileName/Description for our TUN leftovers.
var nlaNamePrefixes = []string{
	"PathologyTunnel",
	"singbox-tun",
	"singbox_tun",
}

// NLANameMatches reports whether a network profile name/description belongs to
// Hiddify/legacy sing-box TUN adapters (prefix match, case-insensitive).
func NLANameMatches(name string) bool {
	n := strings.TrimSpace(name)
	if n == "" {
		return false
	}
	lower := strings.ToLower(n)
	for _, p := range nlaNamePrefixes {
		pl := strings.ToLower(p)
		if lower == pl || strings.HasPrefix(lower, pl) {
			return true
		}
	}
	return false
}
