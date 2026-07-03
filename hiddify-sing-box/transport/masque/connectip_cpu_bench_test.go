package masque

import (
	"testing"
	"time"
)

func TestGATEConnectIPCPUBudgetL1PipeUpload(t *testing.T) {
	conn, payload := setupConnectIPL1PipeUploadCPUBench(t)
	runCPUBudgetGate(t, cpuSiteConnectIPL1PipeUpload, connectIPL1PipeUploadMaxNsPerB, connectUDPCPUBenchGateWall, func() int64 {
		return benchConnectIPCPUUploadN(t, conn, payload, connectUDPCPUBenchIterBytes)
	})
}

func TestGATEConnectIPCPUBudgetL1PipeDownload(t *testing.T) {
	conn, buf := setupConnectIPL1PipeDownloadCPUBench(t)
	runCPUBudgetGate(t, cpuSiteConnectIPL1PipeDownload, connectIPL1PipeDownloadMaxNsPerB, connectUDPCPUBenchGateWall, func() int64 {
		return benchConnectIPCPUDownloadN(t, conn, buf, connectUDPCPUBenchIterBytes)
	})
}

// TestLocalizeConnectIPCPUBudgetMatrix logs CONNECT-IP CPU budget sites; hard fail if matrix wall exceeded.
func TestLocalizeConnectIPCPUBudgetMatrix(t *testing.T) {
	if testing.Short() {
		t.Skip("short")
	}
	matrixStart := time.Now()
	type siteSpec struct {
		name      string
		maxNsPerB float64
		setup     func(*testing.T) func() int64
	}
	sites := []siteSpec{
		{
			cpuSiteConnectIPL1PipeUpload, connectIPL1PipeUploadMaxNsPerB,
			func(t *testing.T) func() int64 {
				conn, payload := setupConnectIPL1PipeUploadCPUBench(t)
				return func() int64 {
					return benchConnectIPCPUUploadN(t, conn, payload, connectUDPCPUBenchIterBytes)
				}
			},
		},
		{
			cpuSiteConnectIPL1PipeDownload, connectIPL1PipeDownloadMaxNsPerB,
			func(t *testing.T) func() int64 {
				conn, buf := setupConnectIPL1PipeDownloadCPUBench(t)
				return func() int64 {
					return benchConnectIPCPUDownloadN(t, conn, buf, connectUDPCPUBenchIterBytes)
				}
			},
		},
	}
	for _, s := range sites {
		if elapsed := time.Since(matrixStart); elapsed > connectUDPCPUBudgetMatrixWall {
			t.Fatalf("CPU matrix hung: elapsed=%v before site %s (max %v)", elapsed.Round(time.Millisecond), s.name, connectUDPCPUBudgetMatrixWall)
		}
		t.Run(s.name, func(t *testing.T) {
			iter := s.setup(t)
			nsPerB, wall := measureCPUBudgetGate(t, s.name, connectUDPCPUBenchGateWall, connectUDPCPUBenchGateBytes, iter)
			logCPUBudgetLine(t, s.name, cpuSiteCodeRef[s.name], nsPerB, s.maxNsPerB, wall)
			if nsPerB > s.maxNsPerB {
				t.Logf("OPEN: %s", synthKPIDiagnostic(s.name, "cpu_ns_per_b", nsPerB, s.maxNsPerB,
					"CPU budget localize — not hard GATE unless regression"))
			}
		})
	}
	t.Logf("CPU matrix total wall=%v", time.Since(matrixStart).Round(time.Millisecond))
}
