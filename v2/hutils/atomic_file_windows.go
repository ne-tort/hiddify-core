//go:build windows

package hutils

import (
	"os"

	"golang.org/x/sys/windows"
)

func replaceFile(tmp, path string) error {
	if err := os.Rename(tmp, path); err == nil {
		return nil
	}

	from, err := windows.UTF16PtrFromString(tmp)
	if err != nil {
		return replaceWithBak(tmp, path)
	}
	to, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return replaceWithBak(tmp, path)
	}
	flags := uint32(windows.MOVEFILE_REPLACE_EXISTING | windows.MOVEFILE_WRITE_THROUGH)
	if err := windows.MoveFileEx(from, to, flags); err == nil {
		return nil
	}
	return replaceWithBak(tmp, path)
}
