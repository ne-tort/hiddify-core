package masque

// Bench-shaped throughput (tcp_down > 21 Mbit/s) is validated on VPS via masque-vps-bench.
// In-process pacing harnesses are flaky with io.Pipe + background feeder; see
// TestConnectStreamDownloadFeederDuplexInflightBounded and connect_stream_duplex_test.go.
