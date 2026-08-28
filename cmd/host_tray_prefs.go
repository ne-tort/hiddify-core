package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
)

type hostTrayPrefs struct {
	Locale    string
	ThemeMode string
	AutoConnectOnLogin bool
}

func loadHostTrayPrefs(basePath string) hostTrayPrefs {
	prefs := hostTrayPrefs{Locale: hostTrayLang, ThemeMode: "system"}
	if basePath == "" {
		return prefs
	}

	candidates := []string{
		filepath.Join(basePath, "shared_preferences.json"),
	}

	for _, path := range candidates {
		raw, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		var store map[string]json.RawMessage
		if err := json.Unmarshal(raw, &store); err != nil {
			continue
		}
		readPref := func(keys ...string) string {
			for _, key := range keys {
				if v, ok := store[key]; ok {
					var s string
					if json.Unmarshal(v, &s) == nil && s != "" {
						return s
					}
				}
			}
			return ""
		}
		if locale := readPref("flutter.locale", "portable.flutter.locale", "locale", "portable.locale"); locale != "" {
			prefs.Locale = strings.ToLower(locale)
			if idx := strings.Index(prefs.Locale, "_"); idx > 0 {
				prefs.Locale = prefs.Locale[:idx]
			}
		}
		if theme := readPref("flutter.theme_mode", "portable.flutter.theme_mode", "theme_mode", "portable.theme_mode"); theme != "" {
			prefs.ThemeMode = strings.ToLower(theme)
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
					prefs.AutoConnectOnLogin = true
				}
			}
		}
		break
	}

	if prefs.Locale == "" {
		prefs.Locale = hostTrayLang
	}
	return prefs
}

func (p hostTrayPrefs) isDarkMenu() bool {
	switch p.ThemeMode {
	case "dark", "black":
		return true
	default:
		return false
	}
}

func (p hostTrayPrefs) isRu() bool {
	return strings.HasPrefix(strings.ToLower(p.Locale), "ru")
}
