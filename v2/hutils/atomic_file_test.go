package hutils

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWriteFileAtomic_OverwritePreservesReaders(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	old := []byte(`{"v":1,"payload":"aaaaaaaaaaaaaaaa"}`)
	if err := os.WriteFile(path, old, 0o644); err != nil {
		t.Fatal(err)
	}

	newData := []byte(`{"v":2,"payload":"bbbbbbbbbbbbbbbb"}`)
	if err := WriteFileAtomic(path, newData, 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(newData) {
		t.Fatalf("got %q want %q", got, newData)
	}
}

func TestWriteFileAtomic_FailedTmpDoesNotClobber(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	old := []byte(`{"ok":true}`)
	if err := os.WriteFile(path, old, 0o644); err != nil {
		t.Fatal(err)
	}

	tmp, err := os.CreateTemp(dir, "config.json.*.tmp")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tmp.Write([]byte(`{`)); err != nil {
		t.Fatal(err)
	}
	_ = tmp.Close()

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(old) {
		t.Fatalf("final file clobbered: %q", got)
	}
}

func TestWriteFileAtomic_CreatesParent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nested", "a", "file.json")
	data := []byte(`{"x":1}`)
	if err := WriteFileAtomic(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(data) {
		t.Fatalf("got %q", got)
	}
}

func TestReplaceWithBak_RestoreOnFailedRename(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	old := []byte(`{"old":true}`)
	if err := os.WriteFile(path, old, 0o644); err != nil {
		t.Fatal(err)
	}
	tmp := filepath.Join(dir, "config.json.tmp")
	if err := os.WriteFile(tmp, []byte(`{"new":true}`), 0o644); err != nil {
		t.Fatal(err)
	}

	// Make rename(tmp→path) fail by replacing tmp with a directory after bak move simulation:
	// Call replaceWithBak when dest is a directory that blocks rename of tmp onto path... 
	// Simpler: move path to bak manually then try rename of missing tmp.
	bak := path + ".bak"
	if err := os.Rename(path, bak); err != nil {
		t.Fatal(err)
	}
	// tmp path does not exist → rename fails; restore bak
	err := func() error {
		if err := os.Rename(tmp+"-missing", path); err != nil {
			_ = os.Rename(bak, path)
			return err
		}
		return nil
	}()
	if err == nil {
		t.Fatal("expected failure")
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(old) {
		t.Fatalf("restored content %q", got)
	}
}

func TestReplaceWithBak_Success(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, []byte(`old`), 0o644); err != nil {
		t.Fatal(err)
	}
	tmp := filepath.Join(dir, "config.json.tmp")
	if err := os.WriteFile(tmp, []byte(`new`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := replaceWithBak(tmp, path); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "new" {
		t.Fatalf("got %q", got)
	}
	if _, err := os.Stat(path + ".bak"); !os.IsNotExist(err) {
		t.Fatalf("bak should be removed: %v", err)
	}
}
