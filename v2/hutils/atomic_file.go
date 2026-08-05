package hutils

import (
	"os"
	"path/filepath"
	"runtime"
)

// WriteFileAtomic writes data to a temp file in the same directory as path,
// syncs, then replaces the target so readers never see a truncated file.
// On failure it does not destroy an existing target; orphan tmps are kept
// when the destination is missing so data is not lost.
func WriteFileAtomic(path string, data []byte, perm os.FileMode) (err error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}

	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() {
		if err == nil {
			return
		}
		_ = tmp.Close()
		// Keep tmp if dest is gone — avoid losing both copies.
		if _, e := os.Stat(path); e == nil {
			_ = os.Remove(tmpName)
		}
	}()

	if _, err = tmp.Write(data); err != nil {
		return err
	}
	if err = tmp.Sync(); err != nil {
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}

	if err = replaceFile(tmpName, path); err != nil {
		return err
	}
	if runtime.GOOS != "windows" {
		_ = os.Chmod(path, perm)
	}
	return nil
}

// replaceWithBak moves path aside to path.bak, then renames tmp onto path.
// On failure after moving aside, restores bak → path. Does not delete tmp on failure.
func replaceWithBak(tmp, path string) error {
	bak := path + ".bak"
	_ = os.Remove(bak)

	hadFinal := false
	if _, err := os.Stat(path); err == nil {
		hadFinal = true
		if err := os.Rename(path, bak); err != nil {
			return err
		}
	}

	if err := os.Rename(tmp, path); err != nil {
		if hadFinal {
			_ = os.Rename(bak, path)
		}
		return err
	}
	_ = os.Remove(bak)
	return nil
}
