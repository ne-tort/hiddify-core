package db

import (
	"testing"

	"github.com/syndtr/goleveldb/leveldb/opt"
	tmdb "github.com/tendermint/tm-db"
)

type testRow struct {
	Id    string
	Value string
}

func TestUpdateInsertDoesNotPileLDBFiles(t *testing.T) {
	dir := t.TempDir()
	SetDataDir(dir)
	t.Cleanup(func() {
		_ = CloseAll()
		SetDataDir("")
	})

	table := GetTable[testRow]()
	const n = 80
	for i := 0; i < n; i++ {
		if err := table.UpdateInsert(&testRow{Id: "k", Value: "v"}); err != nil {
			t.Fatalf("UpdateInsert %d: %v", i, err)
		}
	}

	got, err := table.Get("k")
	if err != nil {
		t.Fatal(err)
	}
	if got.Value != "v" {
		t.Fatalf("value=%q", got.Value)
	}

	files := countDBFiles("testRow")
	// Old open/close-per-op grew ~1 SST per write. Singleton must stay well under n.
	if files > 32 {
		t.Fatalf("leveldb file count after %d writes = %d (want <= 32)", n, files)
	}
}

func TestCompactOnBloatedOpen(t *testing.T) {
	dir := t.TempDir()
	SetDataDir(dir)
	t.Cleanup(func() {
		_ = CloseAll()
		SetDataDir("")
	})

	// Reproduce the old open/write/close anti-pattern that piles L0 SSTs.
	const pile = 100
	for i := 0; i < pile; i++ {
		raw, err := tmdb.NewGoLevelDBWithOpts("testRow", dir, &opt.Options{})
		if err != nil {
			t.Fatalf("open %d: %v", i, err)
		}
		key, _ := SerializeKey("k")
		val, _ := Serialize(&testRow{Id: "k", Value: "old"})
		if err := raw.Set(key, val); err != nil {
			_ = raw.Close()
			t.Fatal(err)
		}
		_ = raw.Close()
	}
	before := countDBFiles("testRow")
	if before <= bloatedFileThreshold {
		t.Fatalf("setup pile: got %d files, want > %d", before, bloatedFileThreshold)
	}

	// Singleton open must compact the bloated store, then keep serving.
	table := GetTable[testRow]()
	if err := table.UpdateInsert(&testRow{Id: "k", Value: "new"}); err != nil {
		t.Fatal(err)
	}
	after := countDBFiles("testRow")
	if after >= before {
		t.Fatalf("compact did not shrink files: before=%d after=%d", before, after)
	}
	if after > 64 {
		t.Fatalf("still bloated after compact: %d files", after)
	}
	got, err := table.Get("k")
	if err != nil {
		t.Fatal(err)
	}
	if got.Value != "new" {
		t.Fatalf("value=%q", got.Value)
	}
}
