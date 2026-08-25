package db

import (
	"os"
	"path/filepath"
	"testing"
)

// Optional smoke against a copied portable pile (created next to this package).
func TestRewriteRealPortableCopy(t *testing.T) {
	dir := filepath.Join("testdata_bloated")
	dbDir := filepath.Join(dir, "AppSettings.db")
	entries, err := os.ReadDir(dbDir)
	if err != nil || len(entries) < bloatedFileThreshold {
		t.Skip("testdata_bloated/AppSettings.db not present or not bloated")
	}

	SetDataDir(dir)
	t.Cleanup(func() {
		_ = CloseAll()
		SetDataDir("")
	})

	before := countDBFiles("AppSettings")
	if _, err := getDB("AppSettings"); err != nil {
		t.Fatal(err)
	}
	after := countDBFiles("AppSettings")
	t.Logf("portable copy: %d -> %d files", before, after)
	if after >= before || after > 64 {
		t.Fatalf("rewrite failed to shrink: before=%d after=%d", before, after)
	}
}
