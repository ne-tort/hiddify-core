package asym

import (
	"crypto/rand"
	"encoding/hex"
)

// NewMuxSessionKey returns a per-session mux correlation id for asymmetric legs.
func NewMuxSessionKey() (string, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}
