package masquetls

import (
	"crypto/rand"
	"strings"
	"unicode"
)

// MixedCaseSNI rewrites ASCII letters in a hostname to random/alternating case for wire SNI.
// Certificate hostname matching is case-insensitive, so verify still uses the same DNS name.
func MixedCaseSNI(host string) string {
	host = strings.TrimSpace(host)
	if host == "" {
		return host
	}
	var b strings.Builder
	b.Grow(len(host))
	rnd := make([]byte, (countLetters(host)+7)/8)
	_, rndErr := rand.Read(rnd)
	haveRnd := rndErr == nil
	bit := 0
	altUpper := true
	for _, r := range host {
		if !unicode.IsLetter(r) {
			b.WriteRune(r)
			continue
		}
		upper := altUpper
		if haveRnd {
			upper = (rnd[bit/8]>>(bit%8))&1 == 1
			bit++
		} else {
			altUpper = !altUpper
		}
		if upper {
			b.WriteRune(unicode.ToUpper(r))
		} else {
			b.WriteRune(unicode.ToLower(r))
		}
	}
	out := b.String()
	if out == host && countLetters(host) > 0 {
		return forceAlternatingCase(host)
	}
	return out
}

func countLetters(s string) int {
	n := 0
	for _, r := range s {
		if unicode.IsLetter(r) {
			n++
		}
	}
	return n
}

func forceAlternatingCase(host string) string {
	var b strings.Builder
	b.Grow(len(host))
	upper := true
	for _, r := range host {
		if !unicode.IsLetter(r) {
			b.WriteRune(r)
			continue
		}
		if upper {
			b.WriteRune(unicode.ToUpper(r))
		} else {
			b.WriteRune(unicode.ToLower(r))
		}
		upper = !upper
	}
	return b.String()
}
