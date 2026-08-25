package db

import (
	"os"
	"testing"
)

// TestRepairEnvAppSettings rewrites AppSettings when REPAIR_APPSETTINGS_DIR is set
// to the parent of AppSettings.db (the LevelDB dataDir).
func TestRepairEnvAppSettings(t *testing.T) {
	dir := os.Getenv("REPAIR_APPSETTINGS_DIR")
	if dir == "" {
		t.Skip("REPAIR_APPSETTINGS_DIR not set")
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
	t.Logf("repaired %s: %d -> %d files", dir, before, after)
	if before > bloatedFileThreshold && after > 64 {
		t.Fatalf("still bloated: before=%d after=%d", before, after)
	}
}
