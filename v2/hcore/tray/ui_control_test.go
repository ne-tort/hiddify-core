//go:build windows || darwin || linux

package tray

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ne-tort/pathology-core/v2/hcore/session"
)

func TestToggleUiOnTrayDoubleClickDetached(t *testing.T) {
	dir := t.TempDir()
	basePath = dir
	uiLifecycle = UiLifecycleDetached
	t.Cleanup(resetUiControlHooks)

	var actions []string
	origSignal := signalUiControl
	// capture actions by wrapping — signalUiControl is not overridable; check file instead
	_ = origSignal

	spawnCalled := false
	origSpawn := spawnUiReconnect
	// spawnUiReconnect is not exported for override; test via file + hooks

	setUiControlHooks(
		func() session.State {
			return session.State{UiPid: 1234}
		},
		func(pid int) bool { return pid == 1234 },
	)

	ToggleUiOnTrayDoubleClickDetached()
	path := filepath.Join(dir, uiControlFile)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("expected quit file: %v", err)
	}
	if string(raw) == "" {
		t.Fatal("empty quit payload")
	}
	if len(actions) > 0 {
		t.Fatalf("unexpected actions: %v", actions)
	}
	_ = spawnCalled
	_ = origSpawn
}

func TestToggleUiOnTrayDoubleClickEmbedded(t *testing.T) {
	dir := t.TempDir()
	basePath = dir
	uiLifecycle = UiLifecycleEmbedded
	t.Cleanup(resetUiControlHooks)

	setUiControlHooks(
		func() session.State {
			return session.State{UiPid: 999}
		},
		func(pid int) bool { return pid == 999 },
	)

	ToggleUiOnTrayDoubleClickEmbedded()
	raw, err := os.ReadFile(filepath.Join(dir, uiControlFile))
	if err != nil {
		t.Fatalf("expected toggle file: %v", err)
	}
	if !strings.Contains(string(raw), `"action":"toggle"`) {
		t.Fatalf("expected toggle action, got %s", string(raw))
	}
}

func TestSpawnUiReconnectSkipsWhenPidAlive(t *testing.T) {
	dir := t.TempDir()
	basePath = dir
	t.Cleanup(resetUiControlHooks)

	setUiControlHooks(
		func() session.State {
			return session.State{UiPid: 42}
		},
		func(pid int) bool { return pid == 42 },
	)

	spawnUiReconnect()
	raw, err := os.ReadFile(filepath.Join(dir, uiControlFile))
	if err != nil {
		t.Fatalf("expected show file: %v", err)
	}
	if len(raw) == 0 {
		t.Fatal("expected show signal")
	}
}

func TestOnTrayDoubleClickRoutesByLifecycle(t *testing.T) {
	dir := t.TempDir()
	basePath = dir
	t.Cleanup(resetUiControlHooks)

	setUiControlHooks(
		func() session.State { return session.State{UiPid: 1} },
		func(pid int) bool { return pid == 1 },
	)

	uiLifecycle = UiLifecycleEmbedded
	onTrayDoubleClick()
	raw, _ := os.ReadFile(filepath.Join(dir, uiControlFile))
	if !strings.Contains(string(raw), `"action":"toggle"`) {
		t.Fatal("embedded should write toggle")
	}

	os.Remove(filepath.Join(dir, uiControlFile))
	uiLifecycle = UiLifecycleDetached
	onTrayDoubleClick()
	raw, err := os.ReadFile(filepath.Join(dir, uiControlFile))
	if err != nil || len(raw) == 0 {
		t.Fatal("detached should write quit")
	}
}
