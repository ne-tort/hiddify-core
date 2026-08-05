//go:build !windows

package hutils

import "os"

func replaceFile(tmp, path string) error {
	if err := os.Rename(tmp, path); err == nil {
		return nil
	}
	return replaceWithBak(tmp, path)
}
