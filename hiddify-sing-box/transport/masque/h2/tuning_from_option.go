package h2

import (
	"time"

	"github.com/sagernet/sing-box/option"
)

// TuningFromOption maps JSON h2_tuning onto Tuning (0 fields = keep Resolve defaults).
func TuningFromOption(t *option.MasqueH2TuningOptions) Tuning {
	if t == nil {
		return Tuning{}
	}
	out := Tuning{
		StreamRecvWindow:          int(t.StreamRecvWindow),
		ConnRecvWindow:            int(t.ConnRecvWindow),
		MaxReadFrameSize:          t.MaxReadFrameSize,
		MaxConcurrentStreams:      t.MaxConcurrentStreams,
		UploadBufferPerConnection: int32(t.UploadBufferPerConnection),
		UploadBufferPerStream:     int32(t.UploadBufferPerStream),
		UploadFlushBytes:          int(t.UploadFlushBytes),
		UploadPipeBytes:           int(t.UploadPipeBytes),
		DownloadBufferBytes:       int(t.DownloadBufferBytes),
		DownloadFlushMinBytes:     int(t.DownloadFlushMinBytes),
		ClearIdlePing:             t.DisableIdlePing,
	}
	if t.ReadIdleTimeout > 0 {
		out.ReadIdleTimeout = time.Duration(t.ReadIdleTimeout) * time.Millisecond
	}
	if t.PingTimeout > 0 {
		out.PingTimeout = time.Duration(t.PingTimeout) * time.Millisecond
	}
	if t.DownloadFillWait > 0 {
		out.DownloadFillWait = time.Duration(t.DownloadFillWait) * time.Millisecond
	}
	if t.DownloadFillMaxWall > 0 {
		out.DownloadFillMaxWall = time.Duration(t.DownloadFillMaxWall) * time.Millisecond
	}
	return out
}
