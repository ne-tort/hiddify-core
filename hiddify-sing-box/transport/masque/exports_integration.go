package masque

// Integration exports for protocol/masque prod-stack tests (LaunchMasqueStack + Endpoint + SOCKS).

const (
	ExportConnectStreamSynthProdMinMbps              = connectStreamSynthProdMinMbps
	ExportConnectStreamH2SeqSymmetryMaxRatio         = connectStreamH2SeqSymmetryMaxRatio
	ExportConnectStreamH2AsymDockerBaselineDownMbps  = connectStreamH2AsymDockerBaselineDownMbps
	ExportConnectStreamH2AsymDockerBaselineUpMbps    = connectStreamH2AsymDockerBaselineUpMbps
	ExportConnectStreamH2AsymChunk64BisectUpMbps     = connectStreamH2AsymChunk64BisectUpMbps
	ExportConnectStreamH2AsymEagerOffBisectUpMbps     = connectStreamH2AsymEagerOffBisectUpMbps
	ExportConnectStreamH2AsymRelayWakeOffBisectUpMbps   = connectStreamH2AsymRelayWakeOffBisectUpMbps
	ExportConnectStreamH2AsymUploadOnlyMbps          = connectStreamH2AsymUploadOnlyMbps
	ExportConnectStreamH2AsymDownloadOnlyMbps        = connectStreamH2AsymDownloadOnlyMbps
	ExportConnectStreamH2AsymH3ControlDownMbps       = connectStreamH2AsymH3ControlDownMbps
	ExportConnectStreamH2AsymH3ControlUpMbps         = connectStreamH2AsymH3ControlUpMbps
	ExportConnectStreamH2AsymH3ControlMinRatio       = connectStreamH2AsymH3ControlMinRatio
	ExportConnectStreamH2AsymHypothesisMinUplift     = connectStreamH2AsymHypothesisMinUplift
)

// ExportSynthProdGatePass reports DoD 1000 Mbit/s with −3% Windows in-proc slack (parity UDP synth).
func ExportSynthProdGatePass(mbps float64) bool { return synthProdGatePass(mbps) }

// SynthKPIDiagnostic formats a synth GATE failure message for inttest KPI gates.
func SynthKPIDiagnostic(layer, leg string, gotMbps, wantMbps float64, hint string) string {
	return synthKPIDiagnostic(layer, leg, gotMbps, wantMbps, hint)
}
