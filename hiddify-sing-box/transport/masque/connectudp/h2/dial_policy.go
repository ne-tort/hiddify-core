package h2

import (
	"os"
	"strconv"
	"strings"
)

const (
	envH2ConnectUDPAsymmetricDuplex = "MASQUE_H2_CONNECT_UDP_ASYMMETRIC_DUPLEX"
	envH2ConnectUDPUploadStreams    = "MASQUE_H2_CONNECT_UDP_UPLOAD_STREAMS"
)

// ConnectUDPDialPolicy holds H2 CONNECT-UDP dial shape knobs (W-UDP-4 PR0).
// Parsed once per DialH2Overlay instead of repeated os.Getenv in hot dial path.
type ConnectUDPDialPolicy struct {
	AsymmetricDuplex bool
	UploadStreams    int
}

// ConnectUDPDialPolicyFromEnv reads MASQUE_H2_CONNECT_UDP_* env once.
func ConnectUDPDialPolicyFromEnv() ConnectUDPDialPolicy {
	return ConnectUDPDialPolicy{
		AsymmetricDuplex: parseAsymmetricDuplexEnv(),
		UploadStreams:    parseUploadStreamsEnv(),
	}
}

func parseAsymmetricDuplexEnv() bool {
	v := strings.TrimSpace(os.Getenv(envH2ConnectUDPAsymmetricDuplex))
	if v == "" {
		return true
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return true
	}
	return b
}

func parseUploadStreamsEnv() int {
	v := strings.TrimSpace(os.Getenv(envH2ConnectUDPUploadStreams))
	if v == "" {
		return 1
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 1 {
		return 1
	}
	if n > 8 {
		return 8
	}
	return n
}
