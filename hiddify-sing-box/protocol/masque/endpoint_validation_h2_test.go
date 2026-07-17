package masque

import (
	"testing"

	"github.com/sagernet/sing-box/option"
)

func TestH2ProfileRemoved(t *testing.T) {
	t.Parallel()
	opts := applyMasqueClientMasqueDefaults(optionMasqueClient(""))
	opts.H2Profile = "browser"
	if err := validateMasqueOptions(opts); err == nil {
		t.Fatal("expected h2_profile rejected")
	}
}

func TestValidateH2Tuning(t *testing.T) {
	t.Parallel()
	opts := applyMasqueClientMasqueDefaults(optionMasqueClient(""))
	opts.H2Tuning = &option.MasqueH2TuningOptions{
		MaxReadFrameSize:     16 << 10,
		MaxConcurrentStreams: 500,
		DownloadFillWait:     5,
		DownloadFillMaxWall:  20,
	}
	if err := validateMasqueOptions(opts); err != nil {
		t.Fatal(err)
	}
	opts.H2Tuning = &option.MasqueH2TuningOptions{MaxReadFrameSize: 100}
	if err := validateMasqueOptions(opts); err == nil {
		t.Fatal("expected tiny max_read_frame_size rejected")
	}
	opts.H2Tuning = &option.MasqueH2TuningOptions{DownloadFillWait: 50, DownloadFillMaxWall: 10}
	if err := validateMasqueOptions(opts); err == nil {
		t.Fatal("expected fill_wait > max_wall rejected")
	}
	opts.H2Tuning = &option.MasqueH2TuningOptions{DownloadFlushMinBytes: 8 << 20} // > default 4MiB buffer
	if err := validateMasqueOptions(opts); err == nil {
		t.Fatal("expected flush_min > default buffer rejected")
	}
	opts.H2Tuning = &option.MasqueH2TuningOptions{DownloadFillWait: 50} // > default wall 40ms
	if err := validateMasqueOptions(opts); err == nil {
		t.Fatal("expected fill_wait > default max_wall rejected")
	}
	opts.H2Tuning = &option.MasqueH2TuningOptions{MaxReadFrameSize: 1 << 24} // 16777216 > RFC max
	if err := validateMasqueOptions(opts); err == nil {
		t.Fatal("expected max_read_frame_size 2^24 rejected")
	}
}
