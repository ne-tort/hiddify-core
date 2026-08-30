//go:build windows || darwin || linux

package tray

import (
	"embed"
	"encoding/json"
	"strings"
)

//go:embed i18n/*.json
var i18nFS embed.FS

type localeStrings struct {
	ShowWindow      string `json:"showWindow"`
	Connect         string `json:"connect"`
	Disconnect      string `json:"disconnect"`
	Reconnect       string `json:"reconnect"`
	Quit            string `json:"quit"`
	Connecting      string `json:"connecting"`
	Disconnecting   string `json:"disconnecting"`
	ServiceMode     string `json:"serviceMode"`
	ModeProxy       string `json:"modeProxy"`
	ModeSystemProxy string `json:"modeSystemProxy"`
	ModeTun         string `json:"modeTun"`
	Profiles        string `json:"profiles"`
}

var (
	i18nCache = map[string]localeStrings{}
	i18nEn    localeStrings
)

func init() {
	raw, err := i18nFS.ReadFile("i18n/en.json")
	if err == nil {
		_ = json.Unmarshal(raw, &i18nEn)
		i18nCache["en"] = i18nEn
	}
	for _, loc := range []string{"ru", "ar", "es", "fa", "fr", "id", "pt-br", "tr", "zh-cn", "zh-tw"} {
		raw, err := i18nFS.ReadFile("i18n/" + loc + ".json")
		if err != nil {
			continue
		}
		var s localeStrings
		if json.Unmarshal(raw, &s) == nil {
			i18nCache[loc] = s
		}
	}
}

func labelsForLocale(locale string) localeStrings {
	loc := normalizeLocale(locale)
	if s, ok := i18nCache[loc]; ok {
		return s
	}
	if idx := strings.Index(loc, "-"); idx > 0 {
		if s, ok := i18nCache[loc[:idx]]; ok {
			return s
		}
	}
	return i18nEn
}
