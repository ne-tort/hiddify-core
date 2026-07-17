package pathbuild

import (
	"crypto/rand"
	"encoding/base64"
	"strconv"
	"strings"

	E "github.com/sagernet/sing/common/exceptions"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	opaqueHostPortSep = "\x00"
	opaqueKeySize     = chacha20poly1305.KeySize // 32
)

// defaultObfuscationKey is a compile-time shared key used when path_obfuscation=true.
// It is intentionaly public (lives in the binary): the goal is to break DPI path signatures
// (no plaintext host/port in :path), not to provide confidentiality against a targeted adversary.
var defaultObfuscationKey = [opaqueKeySize]byte{
	0x6d, 0x61, 0x73, 0x71, 0x75, 0x65, 0x2d, 0x70, // "masque-p"
	0x61, 0x74, 0x68, 0x2d, 0x6f, 0x62, 0x66, 0x31, // "ath-obf1"
	0xc0, 0xff, 0xee, 0x11, 0x22, 0x33, 0x44, 0x55,
	0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
}

// ActiveKey returns the baked-in key when obfuscation is enabled, else nil.
func ActiveKey(enabled bool) ObfuscationKey {
	if !enabled {
		return nil
	}
	k := make([]byte, opaqueKeySize)
	copy(k, defaultObfuscationKey[:])
	return k
}

// SealHostPort encrypts host+port into a single base64url opaque path segment (random nonce).
func SealHostPort(key []byte, host string, port uint16) (string, error) {
	if len(key) != opaqueKeySize {
		return "", E.New("invalid path obfuscation key length")
	}
	host = strings.TrimSpace(host)
	if host == "" || port == 0 {
		return "", E.New("obfuscation requires non-empty host and non-zero port")
	}
	pt := []byte(host + opaqueHostPortSep + strconv.Itoa(int(port)))
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	ct := aead.Seal(nil, nonce, pt, nil)
	out := make([]byte, 0, len(nonce)+len(ct))
	out = append(out, nonce...)
	out = append(out, ct...)
	return base64.RawURLEncoding.EncodeToString(out), nil
}

// OpenHostPort decrypts an opaque path segment into host and port.
func OpenHostPort(key []byte, opaque string) (host string, port uint16, err error) {
	if len(key) != opaqueKeySize {
		return "", 0, E.New("invalid path obfuscation key length")
	}
	opaque = strings.TrimSpace(opaque)
	if opaque == "" {
		return "", 0, E.New("empty opaque path segment")
	}
	raw, err := base64.RawURLEncoding.DecodeString(opaque)
	if err != nil {
		return "", 0, E.Cause(err, "decode opaque path")
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return "", 0, err
	}
	ns := aead.NonceSize()
	if len(raw) < ns+aead.Overhead() {
		return "", 0, E.New("opaque path too short")
	}
	nonce, ct := raw[:ns], raw[ns:]
	pt, err := aead.Open(nil, nonce, ct, nil)
	if err != nil {
		return "", 0, E.New("opaque path decrypt failed")
	}
	parts := strings.SplitN(string(pt), opaqueHostPortSep, 2)
	if len(parts) != 2 {
		return "", 0, E.New("opaque path plaintext malformed")
	}
	host = strings.TrimSpace(parts[0])
	p, err := strconv.Atoi(strings.TrimSpace(parts[1]))
	if err != nil || p <= 0 || p > 65535 {
		return "", 0, E.New("opaque path port invalid")
	}
	if host == "" {
		return "", 0, E.New("opaque path host empty")
	}
	return host, uint16(p), nil
}

// SealIPScope encrypts CONNECT-IP target+ipproto into one opaque segment.
func SealIPScope(key []byte, target string, ipproto uint8) (string, error) {
	if len(key) != opaqueKeySize {
		return "", E.New("invalid path obfuscation key length")
	}
	target = strings.TrimSpace(target)
	if target == "" {
		target = "0.0.0.0/0"
	}
	pt := []byte(target + opaqueHostPortSep + strconv.Itoa(int(ipproto)))
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	ct := aead.Seal(nil, nonce, pt, nil)
	out := make([]byte, 0, len(nonce)+len(ct))
	out = append(out, nonce...)
	out = append(out, ct...)
	return base64.RawURLEncoding.EncodeToString(out), nil
}

// OpenIPScope decrypts CONNECT-IP opaque segment.
func OpenIPScope(key []byte, opaque string) (target string, ipproto uint8, err error) {
	if len(key) != opaqueKeySize {
		return "", 0, E.New("invalid path obfuscation key length")
	}
	opaque = strings.TrimSpace(opaque)
	raw, err := base64.RawURLEncoding.DecodeString(opaque)
	if err != nil {
		return "", 0, E.Cause(err, "decode opaque path")
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return "", 0, err
	}
	ns := aead.NonceSize()
	if len(raw) < ns+aead.Overhead() {
		return "", 0, E.New("opaque path too short")
	}
	pt, err := aead.Open(nil, raw[:ns], raw[ns:], nil)
	if err != nil {
		return "", 0, E.New("opaque path decrypt failed")
	}
	parts := strings.SplitN(string(pt), opaqueHostPortSep, 2)
	if len(parts) != 2 {
		return "", 0, E.New("opaque path plaintext malformed")
	}
	target = strings.TrimSpace(parts[0])
	n, err := strconv.Atoi(strings.TrimSpace(parts[1]))
	if err != nil || n < 0 || n > 255 {
		return "", 0, E.New("opaque path ipproto invalid")
	}
	if target == "" {
		return "", 0, E.New("opaque path target empty")
	}
	return target, uint8(n), nil
}
