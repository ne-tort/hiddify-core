//go:build windows || darwin || linux

package tray

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	hcore "github.com/ne-tort/pathology-core/v2/hcore"
)

type prefs struct {
	Locale             string
	ThemeMode          string
	AutoConnectOnLogin bool
}

func loadPrefs(basePath, fallbackLang string) prefs {
	out := prefs{Locale: fallbackLang, ThemeMode: "system"}

	// Authoritative when UI has synced session (HeadlessSessionSync).
	st := hcore.SessionGetState()
	if st.Locale != "" {
		out.Locale = normalizeLocale(st.Locale)
	}
	if st.ThemeMode != "" {
		out.ThemeMode = strings.ToLower(st.ThemeMode)
	}

	filePrefs := loadPrefsFromFile(basePath, fallbackLang)
	if out.Locale == fallbackLang && filePrefs.Locale != "" {
		out.Locale = filePrefs.Locale
	}
	if out.ThemeMode == "system" && filePrefs.ThemeMode != "" && filePrefs.ThemeMode != "system" {
		out.ThemeMode = filePrefs.ThemeMode
	} else if out.ThemeMode == "" && filePrefs.ThemeMode != "" {
		out.ThemeMode = filePrefs.ThemeMode
	}
	if filePrefs.AutoConnectOnLogin {
		out.AutoConnectOnLogin = true
	}
	if out.Locale == "" {
		out.Locale = fallbackLang
	}
	if out.ThemeMode == "" {
		out.ThemeMode = "system"
	}
	return out
}

func loadPrefsFromFile(basePath, fallbackLang string) prefs {
	out := prefs{Locale: fallbackLang, ThemeMode: "system"}
	if basePath == "" {
		return out
	}
	for _, path := range prefsFileCandidates(basePath) {
		raw, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		var store map[string]json.RawMessage
		if json.Unmarshal(raw, &store) != nil {
			continue
		}
		if loc := scanStringKey(store, "locale"); loc != "" {
			out.Locale = normalizeLocale(loc)
		}
		if theme := scanStringKey(store, "theme_mode"); theme != "" {
			out.ThemeMode = strings.ToLower(theme)
		}
		for _, key := range []string{
			"flutter.auto_connect_on_login",
			"portable.flutter.auto_connect_on_login",
			"auto_connect_on_login",
			"portable.auto_connect_on_login",
		} {
			if v, ok := store[key]; ok {
				var b bool
				if json.Unmarshal(v, &b) == nil && b {
					out.AutoConnectOnLogin = true
				}
			}
		}
		break
	}
	return out
}

func prefsFileCandidates(basePath string) []string {
	return []string{
		filepath.Join(basePath, "shared_preferences.json"),
	}
}

// scanStringKey finds a string value for keys named exactly [suffix] or *.[suffix].
func scanStringKey(store map[string]json.RawMessage, suffix string) string {
	for key, raw := range store {
		if key != suffix && !strings.HasSuffix(key, "."+suffix) {
			continue
		}
		var s string
		if json.Unmarshal(raw, &s) == nil && s != "" {
			return s
		}
	}
	return ""
}

func (p prefs) isDarkMenu() bool {
	return resolveDarkMenu(p)
}

func (p prefs) isRu() bool {
	return strings.HasPrefix(strings.ToLower(p.Locale), "ru")
}

func LoadPrefs(basePath, fallbackLang string) (locale string, autoConnect bool) {
	p := loadPrefs(basePath, fallbackLang)
	return p.Locale, p.AutoConnectOnLogin
}

func normalizeLocale(raw string) string {
	loc := strings.ToLower(strings.TrimSpace(raw))
	switch loc {
	case "zh", "zh_cn", "zhcn":
		return "zh-cn"
	case "zh_tw", "zhtw":
		return "zh-tw"
	case "pt_br", "ptbr":
		return "pt-br"
	}
	if idx := strings.Index(loc, "_"); idx > 0 {
		loc = loc[:idx]
	}
	return loc
}
