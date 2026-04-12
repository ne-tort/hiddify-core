package awg

import (
	"encoding/base64"
	"encoding/hex"
	"net/netip"
	"strings"

	E "github.com/sagernet/sing/common/exceptions"
	F "github.com/sagernet/sing/common/format"
	M "github.com/sagernet/sing/common/metadata"
)

// buildIpcConfig turns EndpointOptions + peers into an amneziawg UAPI "set" string.
// Device keys (private_key, listen_port, jc, jmin, jmax, s1–s4, h1–h4, i1–i5) are emitted
// before the first public_key so handleDeviceLine receives them (see amneziawg-go IpcSetOperation).
// Integer fields jc/jmin/jmax are omitted when zero (same as unset); when non-zero they must be
// positive per amneziawg-go. s1–s4 are omitted when zero — explicit zero padding cannot be expressed
// with JSON numbers alone (omit vs 0); use upstream defaults if you need sN=0 while other obfs set.
func validateAwgNumericObfuscation(opts EndpointOptions) error {
	if opts.Jc < 0 || opts.Jmin < 0 || opts.Jmax < 0 {
		return E.New("amneziawg: jc, jmin, jmax must be non-negative")
	}
	if opts.S1 < 0 || opts.S2 < 0 || opts.S3 < 0 || opts.S4 < 0 {
		return E.New("amneziawg: s1, s2, s3, s4 must be non-negative")
	}
	// When a key is present in UAPI, amneziawg-go requires jc/jmin/jmax > 0 (see handleDeviceLine).
	// We only emit non-zero values; a lone non-zero jc with jmin/jmax omitted is still a valid IPC pattern.
	return nil
}

type peerConfig struct {
	destination     M.Socksaddr
	endpoint        netip.AddrPort
	publicKeyHex    string
	preSharedKeyHex string
	allowedIPs      []netip.Prefix
	keepalive       uint16
	reserved        [3]uint8
}

func parsePeerConfigs(peers []PeerOptions) ([]peerConfig, error) {
	out := make([]peerConfig, 0, len(peers))
	for peerIndex, raw := range peers {
		if len(raw.AllowedIPs) == 0 {
			return nil, E.New("missing allowed ips for peer ", peerIndex)
		}
		p := peerConfig{
			allowedIPs: raw.AllowedIPs,
			keepalive:  raw.PersistentKeepaliveInterval,
		}
		publicKeyBytes, err := base64.StdEncoding.DecodeString(raw.PublicKey)
		if err != nil {
			return nil, E.Cause(err, "decode public key for peer ", peerIndex)
		}
		p.publicKeyHex = hex.EncodeToString(publicKeyBytes)
		if raw.PreSharedKey != "" {
			preSharedKeyBytes, err := base64.StdEncoding.DecodeString(raw.PreSharedKey)
			if err != nil {
				return nil, E.Cause(err, "decode pre shared key for peer ", peerIndex)
			}
			p.preSharedKeyHex = hex.EncodeToString(preSharedKeyBytes)
		}
		if raw.Endpoint.Addr.IsValid() {
			p.endpoint = netip.AddrPortFrom(raw.Endpoint.Addr, raw.Endpoint.Port)
		} else if raw.Endpoint.IsFqdn() {
			p.destination = raw.Endpoint
		}
		if len(raw.Reserved) > 0 {
			if len(raw.Reserved) != 3 {
				return nil, E.New("invalid reserved value for peer ", peerIndex, ", required 3 bytes, got ", len(raw.Reserved))
			}
			copy(p.reserved[:], raw.Reserved[:])
		}
		out = append(out, p)
	}
	return out, nil
}

func buildIpcConfig(opts EndpointOptions, peers []peerConfig) (string, error) {
	if err := validateAwgNumericObfuscation(opts); err != nil {
		return "", err
	}
	privateKeyBytes, err := base64.StdEncoding.DecodeString(opts.PrivateKey)
	if err != nil {
		return "", E.Cause(err, "decode private key")
	}
	var b strings.Builder
	b.WriteString("private_key=")
	b.WriteString(hex.EncodeToString(privateKeyBytes))
	if opts.ListenPort != 0 {
		b.WriteString("\nlisten_port=")
		b.WriteString(F.ToString(opts.ListenPort))
	}
	if opts.Jc != 0 {
		b.WriteString("\njc=")
		b.WriteString(F.ToString(opts.Jc))
	}
	if opts.Jmin != 0 {
		b.WriteString("\njmin=")
		b.WriteString(F.ToString(opts.Jmin))
	}
	if opts.Jmax != 0 {
		b.WriteString("\njmax=")
		b.WriteString(F.ToString(opts.Jmax))
	}
	if opts.S1 != 0 {
		b.WriteString("\ns1=")
		b.WriteString(F.ToString(opts.S1))
	}
	if opts.S2 != 0 {
		b.WriteString("\ns2=")
		b.WriteString(F.ToString(opts.S2))
	}
	if opts.S3 != 0 {
		b.WriteString("\ns3=")
		b.WriteString(F.ToString(opts.S3))
	}
	if opts.S4 != 0 {
		b.WriteString("\ns4=")
		b.WriteString(F.ToString(opts.S4))
	}
	if opts.H1 != "" {
		b.WriteString("\nh1=")
		b.WriteString(opts.H1)
	}
	if opts.H2 != "" {
		b.WriteString("\nh2=")
		b.WriteString(opts.H2)
	}
	if opts.H3 != "" {
		b.WriteString("\nh3=")
		b.WriteString(opts.H3)
	}
	if opts.H4 != "" {
		b.WriteString("\nh4=")
		b.WriteString(opts.H4)
	}
	if opts.I1 != "" {
		b.WriteString("\ni1=")
		b.WriteString(opts.I1)
	}
	if opts.I2 != "" {
		b.WriteString("\ni2=")
		b.WriteString(opts.I2)
	}
	if opts.I3 != "" {
		b.WriteString("\ni3=")
		b.WriteString(opts.I3)
	}
	if opts.I4 != "" {
		b.WriteString("\ni4=")
		b.WriteString(opts.I4)
	}
	if opts.I5 != "" {
		b.WriteString("\ni5=")
		b.WriteString(opts.I5)
	}
	for _, peer := range peers {
		b.WriteString("\npublic_key=")
		b.WriteString(peer.publicKeyHex)
		if peer.preSharedKeyHex != "" {
			b.WriteString("\npreshared_key=")
			b.WriteString(peer.preSharedKeyHex)
		}
		b.WriteString("\nprotocol_version=1")
		if peer.endpoint.IsValid() {
			b.WriteString("\nendpoint=")
			b.WriteString(peer.endpoint.String())
		}
		if peer.keepalive > 0 {
			b.WriteString("\npersistent_keepalive_interval=")
			b.WriteString(F.ToString(peer.keepalive))
		}
		for _, allowedIP := range peer.allowedIPs {
			b.WriteString("\nallowed_ip=")
			b.WriteString(allowedIP.String())
		}
	}
	return b.String(), nil
}
