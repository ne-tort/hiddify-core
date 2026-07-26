package ray2sing

// LX-STUB: wireguard-go/hiddify NoiseOptions are absent in lx wireguard-go.
// Noise/fake-packet knobs are ignored at this preliminary engine-swap stage.

func getWireGuardNoise(d map[string]string, addDefault bool) struct{} {
	_ = d
	_ = addDefault
	return struct{}{}
}

func defaultWireguardNoiseOptions() struct{} {
	return struct{}{}
}
