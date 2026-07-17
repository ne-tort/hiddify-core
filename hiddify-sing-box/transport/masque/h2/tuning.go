package h2

import "time"

// Tuning holds optional JSON overrides (h2_tuning). Zero fields mean "keep default".
type Tuning struct {
	StreamRecvWindow          int
	ConnRecvWindow            int
	MaxReadFrameSize          uint32
	MaxConcurrentStreams      uint32
	UploadBufferPerConnection int32
	UploadBufferPerStream     int32
	ReadIdleTimeout           time.Duration // client; >0 sets
	PingTimeout               time.Duration
	// ClearIdlePing forces ReadIdleTimeout/PingTimeout to 0 (lab bulk — no idle PING).
	ClearIdlePing bool
	UploadFlushBytes          int
	UploadPipeBytes           int
	DownloadBufferBytes       int
	DownloadFillWait          time.Duration
	DownloadFlushMinBytes     int
	DownloadFillMaxWall       time.Duration
}

// AutoUploadFlushBytes: frame-sized flush when max frame ≤16 KiB; else 256 KiB.
func AutoUploadFlushBytes(maxReadFrame uint32) int {
	const (
		chromeFrame = 16 << 10
		bulkFlush   = 256 << 10
	)
	if maxReadFrame > 0 && maxReadFrame <= chromeFrame {
		return int(maxReadFrame)
	}
	return bulkFlush
}
