package hcore

import (
	"encoding/json"

	"github.com/ne-tort/pathology-core/v2/db"
	hcommon "github.com/ne-tort/pathology-core/v2/hcommon"
	"github.com/ne-tort/pathology-core/v2/hcore/session"
)

func sessionApplyServiceMode(mode string) error {
	settings := db.GetTable[hcommon.AppSettings]()
	val, err := settings.Get("ClientSettingsJson")
	if err != nil || val == nil {
		return nil
	}
	jsonStr, ok := val.Value.(string)
	if !ok || jsonStr == "" {
		return nil
	}
	var doc map[string]any
	if err := json.Unmarshal([]byte(jsonStr), &doc); err != nil {
		return err
	}
	enableTun, setSystemProxy := sessionServiceModeFlags(mode)
	doc["enable-tun"] = enableTun
	doc["set-system-proxy"] = setSystemProxy
	raw, err := json.Marshal(doc)
	if err != nil {
		return err
	}
	patched := string(raw)
	settings.UpdateInsert(&hcommon.AppSettings{Id: "ClientSettingsJson", Value: patched})
	_, err = ChangeClientSettings(&ChangeClientSettingsRequest{ClientSettingsJson: patched}, false)
	return err
}

func sessionServiceModeFlags(mode string) (enableTun, setSystemProxy bool) {
	switch mode {
	case "proxy":
		return false, false
	case "system-proxy":
		return false, true
	default:
		return true, false
	}
}

// SessionSetServiceMode updates mode in LevelDB and patches client settings when present.
func SessionSetServiceMode(mode string) (session.State, error) {
	st, err := session.SetServiceMode(mode)
	if err != nil {
		return st, err
	}
	if err := sessionApplyServiceMode(mode); err != nil {
		return st, err
	}
	return st, nil
}
