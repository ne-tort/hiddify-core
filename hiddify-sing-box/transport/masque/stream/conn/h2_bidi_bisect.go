package conn

// h2BidiPokeEnabled gates per-chunk upload poke + bootstrap DATA (Invisv has neither).
var h2BidiPokeEnabled = true

// SetH2BidiPokeEnabled toggles pokeUploadPathForH2BidiDownload and bootstrap upload DATA (bisect / unit tests only).
func SetH2BidiPokeEnabled(on bool) {
	h2BidiPokeEnabled = on
}

// H2BidiPokeEnabled reports the bisect bidi-poke toggle.
func H2BidiPokeEnabled() bool {
	return h2BidiPokeEnabled
}
