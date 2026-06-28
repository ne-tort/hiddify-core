package masque

// Integration exports for protocol/masque prod-stack tests (LaunchMasqueStack + Endpoint + SOCKS).

const (
	ExportConnectStreamSynthProdMinMbps       = connectStreamSynthProdMinMbps
	ExportConnectStreamH2SeqSymmetryMaxRatio  = connectStreamH2SeqSymmetryMaxRatio
)

// ExportSynthProdGatePass reports DoD 1000 Mbit/s with −3% Windows in-proc slack (parity UDP synth).
func ExportSynthProdGatePass(mbps float64) bool { return synthProdGatePass(mbps) }

// SynthKPIDiagnostic formats a synth GATE failure message for inttest KPI gates.
func SynthKPIDiagnostic(layer, leg string, gotMbps, wantMbps float64, hint string) string {
	return synthKPIDiagnostic(layer, leg, gotMbps, wantMbps, hint)
}
