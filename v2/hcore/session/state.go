package session

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/ne-tort/pathology-core/v2/db"
	hcommon "github.com/ne-tort/pathology-core/v2/hcommon"
)

// ProfileMeta is a lightweight profile row for tray menus.
type ProfileMeta struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Active bool   `json:"active"`
}

// StartTarget is a resolved sing-box config path for Connect/Reconnect.
type StartTarget struct {
	Path string `json:"path"`
	Name string `json:"name"`
}

// State is the headless session snapshot stored in LevelDB.
type State struct {
	ActiveProfileIDs   []string      `json:"active_profile_ids"`
	DirectMode         bool          `json:"direct_mode"`
	ServiceMode        string        `json:"service_mode"`
	Profiles           []ProfileMeta `json:"profiles"`
	StartTarget        *StartTarget  `json:"start_target,omitempty"`
	DisableMemoryLimit bool          `json:"disable_memory_limit"`
	Locale             string        `json:"locale,omitempty"`
	ThemeMode          string        `json:"theme_mode,omitempty"`
	UiPid              int32         `json:"ui_pid,omitempty"`
}

func settingsTable() *db.Table[hcommon.AppSettings] {
	return db.GetTable[hcommon.AppSettings]()
}

func loadString(key string) (string, bool) {
	val, err := settingsTable().Get(key)
	if err != nil || val == nil {
		return "", false
	}
	s, ok := val.Value.(string)
	return s, ok && s != ""
}

func saveString(key, value string) error {
	return settingsTable().UpdateInsert(&hcommon.AppSettings{Id: key, Value: value})
}

func loadBool(key string) (bool, bool) {
	val, err := settingsTable().Get(key)
	if err != nil || val == nil {
		return false, false
	}
	switch v := val.Value.(type) {
	case bool:
		return v, true
	case string:
		return v == "true" || v == "1", true
	default:
		return false, false
	}
}

func saveBool(key string, value bool) error {
	return settingsTable().UpdateInsert(&hcommon.AppSettings{Id: key, Value: value})
}

func loadInt(key string) (int64, bool) {
	val, err := settingsTable().Get(key)
	if err != nil || val == nil {
		return 0, false
	}
	switch v := val.Value.(type) {
	case int:
		return int64(v), true
	case int64:
		return v, true
	case float64:
		return int64(v), true
	case string:
		var n int64
		if _, err := fmt.Sscan(v, &n); err == nil {
			return n, true
		}
	}
	return 0, false
}

func saveInt(key string, value int32) error {
	return settingsTable().UpdateInsert(&hcommon.AppSettings{Id: key, Value: int64(value)})
}

// LoadState reads session snapshot from LevelDB.
func LoadState() State {
	st := State{ServiceMode: "vpn"}
	if raw, ok := loadString(keyActiveProfileIds); ok {
		_ = json.Unmarshal([]byte(raw), &st.ActiveProfileIDs)
	}
	if v, ok := loadBool(keyDirectMode); ok {
		st.DirectMode = v
	}
	if mode, ok := loadString(keyServiceMode); ok {
		st.ServiceMode = mode
	}
	if raw, ok := loadString(keyProfilesMeta); ok {
		_ = json.Unmarshal([]byte(raw), &st.Profiles)
	}
	if raw, ok := loadString(keyStartTarget); ok {
		var t StartTarget
		if json.Unmarshal([]byte(raw), &t) == nil && t.Path != "" {
			st.StartTarget = &t
		}
	}
	if v, ok := loadBool(keyDisableMemoryLimit); ok {
		st.DisableMemoryLimit = v
	}
	if loc, ok := loadString(keyLocale); ok {
		st.Locale = loc
	}
	if theme, ok := loadString(keyThemeMode); ok {
		st.ThemeMode = theme
	}
	if pid, ok := loadInt(keyUiPid); ok {
		st.UiPid = int32(pid)
	}
	return st
}

// SaveState persists session snapshot to LevelDB.
func SaveState(st State) error {
	if raw, err := json.Marshal(st.ActiveProfileIDs); err == nil {
		if err := saveString(keyActiveProfileIds, string(raw)); err != nil {
			return err
		}
	}
	if err := saveBool(keyDirectMode, st.DirectMode); err != nil {
		return err
	}
	if st.ServiceMode != "" {
		if err := saveString(keyServiceMode, st.ServiceMode); err != nil {
			return err
		}
	}
	if raw, err := json.Marshal(st.Profiles); err == nil {
		if err := saveString(keyProfilesMeta, string(raw)); err != nil {
			return err
		}
	}
	if st.StartTarget != nil && st.StartTarget.Path != "" {
		if raw, err := json.Marshal(st.StartTarget); err == nil {
			if err := saveString(keyStartTarget, string(raw)); err != nil {
				return err
			}
		}
	}
	if err := saveLocaleTheme(st); err != nil {
		return err
	}
	if st.UiPid > 0 {
		if err := saveInt(keyUiPid, st.UiPid); err != nil {
			return err
		}
	}
	return saveBool(keyDisableMemoryLimit, st.DisableMemoryLimit)
}

func saveLocaleTheme(st State) error {
	if st.Locale != "" {
		if err := saveString(keyLocale, st.Locale); err != nil {
			return err
		}
	}
	if st.ThemeMode != "" {
		if err := saveString(keyThemeMode, st.ThemeMode); err != nil {
			return err
		}
	}
	return nil
}

// SyncState merges incoming state and saves it.
func SyncState(in State) (State, error) {
	cur := LoadState()
	// Always mirror active profile ids from UI (including empty = direct-only).
	cur.ActiveProfileIDs = in.ActiveProfileIDs
	cur.DirectMode = in.DirectMode
	if in.ServiceMode != "" {
		cur.ServiceMode = in.ServiceMode
	}
	if len(in.Profiles) > 0 {
		cur.Profiles = in.Profiles
	}
	if in.StartTarget != nil && in.StartTarget.Path != "" {
		cur.StartTarget = in.StartTarget
	}
	cur.DisableMemoryLimit = in.DisableMemoryLimit
	if in.Locale != "" {
		cur.Locale = in.Locale
	}
	if in.ThemeMode != "" {
		cur.ThemeMode = in.ThemeMode
	}
	if in.UiPid > 0 {
		cur.UiPid = in.UiPid
	}
	if err := SaveState(cur); err != nil {
		return cur, err
	}
	return cur, nil
}

// ClearUiPid removes the stored UI process id (after UI exit).
func ClearUiPid() error {
	return settingsTable().Delete(keyUiPid)
}

// ClearUiPidIf removes ui_pid only when it matches expected (avoids clearing a newer UI).
func ClearUiPidIf(expected int32) error {
	if expected <= 0 {
		return ClearUiPid()
	}
	cur := LoadState()
	if cur.UiPid != expected {
		return nil
	}
	return ClearUiPid()
}

// SetActiveProfiles updates active profile ids and profile meta active flags.
func SetActiveProfiles(ids []string) (State, error) {
	if len(ids) == 0 {
		return LoadState(), errors.New("empty profile ids")
	}
	st := LoadState()
	st.ActiveProfileIDs = ids
	active := map[string]struct{}{}
	for _, id := range ids {
		active[id] = struct{}{}
	}
	for i := range st.Profiles {
		_, st.Profiles[i].Active = active[st.Profiles[i].ID]
	}
	if err := SaveState(st); err != nil {
		return st, err
	}
	return st, nil
}

// SetServiceMode updates service mode string (proxy/system-proxy/vpn).
func SetServiceMode(mode string) (State, error) {
	if mode == "" {
		return LoadState(), errors.New("empty service mode")
	}
	st := LoadState()
	st.ServiceMode = mode
	if err := SaveState(st); err != nil {
		return st, err
	}
	return st, nil
}
