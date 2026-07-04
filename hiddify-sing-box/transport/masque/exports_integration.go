package masque

// Integration exports for protocol/masque prod-stack tests (LaunchMasqueStack + Endpoint + SOCKS).

const (
	ExportConnectStreamSynthProdMinMbps              = connectStreamSynthProdMinMbps
	ExportConnectStreamH2SeqSymmetryMaxRatio         = connectStreamH2SeqSymmetryMaxRatio
	ExportConnectStreamH2AsymDockerBaselineDownMbps  = connectStreamH2AsymDockerBaselineDownMbps
	ExportConnectStreamH2AsymDockerBaselineUpMbps    = connectStreamH2AsymDockerBaselineUpMbps
	ExportConnectStreamH2AsymDeepPipeBaselineUpMbps  = connectStreamH2AsymDeepPipeBaselineUpMbps
	ExportConnectStreamH2AsymDeepPipeUploadOnlyMbps  = connectStreamH2AsymDeepPipeUploadOnlyMbps
	ExportConnectStreamH2AsymChunk64BisectUpMbps     = connectStreamH2AsymChunk64BisectUpMbps
	ExportConnectStreamH2AsymEagerOffBisectUpMbps     = connectStreamH2AsymEagerOffBisectUpMbps
	ExportConnectStreamH2AsymRelayWakeOffBisectUpMbps   = connectStreamH2AsymRelayWakeOffBisectUpMbps
	ExportConnectStreamH2AsymUploadOnlyMbps          = connectStreamH2AsymUploadOnlyMbps
	ExportConnectStreamH2AsymDownloadOnlyMbps        = connectStreamH2AsymDownloadOnlyMbps
	ExportConnectStreamH2AsymH3ControlDownMbps       = connectStreamH2AsymH3ControlDownMbps
	ExportConnectStreamH2AsymH3ControlUpMbps         = connectStreamH2AsymH3ControlUpMbps
	ExportConnectStreamH2AsymH3ControlMinRatio       = connectStreamH2AsymH3ControlMinRatio
	ExportConnectStreamH2AsymStockFlushUpMbps        = connectStreamH2AsymStockFlushUpMbps
	ExportConnectStreamH2AsymShallowPipeBisectUpMbps     = connectStreamH2AsymShallowPipeBisectUpMbps
	ExportConnectStreamH2AsymShallowPipeUploadOnlyMbps   = connectStreamH2AsymShallowPipeUploadOnlyMbps
	ExportConnectStreamH2AsymShallowPipeDownloadOnlyMbps = connectStreamH2AsymShallowPipeDownloadOnlyMbps
	ExportConnectStreamH2AsymShallowPipeDownloadMinRatio   = connectStreamH2AsymShallowPipeDownloadMinRatio
	ExportConnectStreamH2AsymShallowPipeSeqDownMbps        = connectStreamH2AsymShallowPipeSeqDownMbps
	ExportConnectStreamH2AsymBidiPokeOffBisectUpMbps     = connectStreamH2AsymBidiPokeOffBisectUpMbps
	ExportConnectStreamH2AsymDeferFCFlushUpMbps          = connectStreamH2AsymDeferFCFlushUpMbps
	ExportConnectStreamH2AsymNoBlockingReadFlushUpMbps   = connectStreamH2AsymNoBlockingReadFlushUpMbps
	ExportConnectStreamH2AsymBulk512UpMbps               = connectStreamH2AsymBulk512UpMbps
	ExportConnectStreamH2AsymBulkFlushDelay10UpMbps      = connectStreamH2AsymBulkFlushDelay10UpMbps
	ExportConnectStreamH2AsymPostH8SeqUpMbps             = connectStreamH2AsymPostH8SeqUpMbps
	ExportConnectStreamH2AsymPostH8SeqDownMbps           = connectStreamH2AsymPostH8SeqDownMbps
	ExportConnectStreamH2AsymPostH8SeqMinRatio           = connectStreamH2AsymPostH8SeqMinRatio
	ExportConnectStreamH2AsymShallowProfileDataFrames    = connectStreamH2AsymShallowProfileDataFrames
	ExportConnectStreamH2AsymShallowProfileTLSFlushes    = connectStreamH2AsymShallowProfileTLSFlushes
	ExportConnectStreamH2AsymShallowProfileMaxFCWaits    = connectStreamH2AsymShallowProfileMaxFCWaits
	ExportConnectStreamH2AsymInvisvCompositeUpMbps         = connectStreamH2AsymInvisvCompositeUpMbps
	ExportConnectStreamH2AsymInvisvCompositeSeqUpMbps    = connectStreamH2AsymInvisvCompositeSeqUpMbps
	ExportConnectStreamH2AsymInvisvCompositeSeqDownMbps  = connectStreamH2AsymInvisvCompositeSeqDownMbps
	ExportConnectStreamH2AsymInvisvCompositeSeqDownMinRatio = connectStreamH2AsymInvisvCompositeSeqDownMinRatio
	ExportConnectStreamH2AsymStockDuplexUpMbps             = connectStreamH2AsymStockDuplexUpMbps
	ExportConnectStreamH2AsymStockDuplexSeqUpMbps          = connectStreamH2AsymStockDuplexSeqUpMbps
	ExportConnectStreamH2AsymStockDuplexSeqDownMbps         = connectStreamH2AsymStockDuplexSeqDownMbps
	ExportConnectStreamH2AsymUploadProfileMaxFCWaits   = connectStreamH2AsymUploadProfileMaxFCWaits
	ExportConnectStreamH2AsymHypothesisMinUplift     = connectStreamH2AsymHypothesisMinUplift
)

// ExportSynthProdGatePass reports DoD 1000 Mbit/s with −3% Windows in-proc slack (parity UDP synth).
func ExportSynthProdGatePass(mbps float64) bool { return synthProdGatePass(mbps) }

// SynthKPIDiagnostic formats a synth GATE failure message for inttest KPI gates.
func SynthKPIDiagnostic(layer, leg string, gotMbps, wantMbps float64, hint string) string {
	return synthKPIDiagnostic(layer, leg, gotMbps, wantMbps, hint)
}
