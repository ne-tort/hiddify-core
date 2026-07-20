package relaystats

import "testing"

func TestCIPRelayStatsRecordAndSnapshot(t *testing.T) {
	EnableForBench()
	Reset()
	RecordC2SPlaneIn(100)
	RecordC2SPlaneIn(50)
	RecordS2CEnqueue()
	RecordS2COut(200)
	RecordS2CWriteFail()
	RecordS2CBatchFlush()
	RecordS2CRTORetransmit()
	NoteDownloadQHigh(7)
	NoteDownloadQHigh(3)
	NoteWriteQHigh(2)
	s := SnapshotNow()
	if s.C2SPlaneIn != 2 || s.C2SPlaneBytes != 150 {
		t.Fatalf("c2s plane got in=%d bytes=%d", s.C2SPlaneIn, s.C2SPlaneBytes)
	}
	if s.S2CEnqueue != 1 || s.S2COut != 1 || s.S2COutBytes != 200 {
		t.Fatalf("s2c out %+v", s)
	}
	if s.S2CWriteFail != 1 || s.S2CBatchFlush != 1 || s.S2CRTORetransmit != 1 {
		t.Fatalf("s2c fails %+v", s)
	}
	if s.DownloadQHigh != 7 || s.WriteQHigh != 2 {
		t.Fatalf("q high down=%d write=%d", s.DownloadQHigh, s.WriteQHigh)
	}
}
