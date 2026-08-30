//go:build windows || darwin || linux

package tray

import (
	"context"
	"path/filepath"

	hcore "github.com/ne-tort/pathology-core/v2/hcore"
	"github.com/fsnotify/fsnotify"
)

func startPrefsWatcher(ctx context.Context, basePath string) {
	if basePath == "" {
		return
	}
	path := filepath.Join(basePath, "shared_preferences.json")
	go func() {
		w, err := fsnotify.NewWatcher()
		if err != nil {
			return
		}
		defer w.Close()

		dir := filepath.Dir(path)
		_ = w.Add(dir)
		// initial load
		refreshTrayDisplay()

		for {
			select {
			case <-ctx.Done():
				return
			case ev, ok := <-w.Events:
				if !ok {
					return
				}
				if ev.Name == path && (ev.Op&fsnotify.Write != 0 || ev.Op&fsnotify.Create != 0) {
					refreshTrayDisplay()
				}
			case _, ok := <-w.Errors:
				if !ok {
					return
				}
			}
		}
	}()
}

func registerDisplaySyncHandler() {
	hcore.SetTrayDisplaySyncHandler(refreshTrayDisplay)
}
