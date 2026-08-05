//go:build windows

package hutils

import (
	"golang.org/x/sys/windows/registry"
)

// cleanupNLAProfiles removes stale Network List profiles/signatures whose
// Description/ProfileName match HiddifyTunnel* or legacy singbox-tun*.
// Best-effort: access-denied and missing keys are ignored.
func cleanupNLAProfiles() {
	cleanupNLATree(`SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles`,
		[]string{"Description", "ProfileName"})
	cleanupNLATree(`SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Unmanaged`,
		[]string{"Description", "ProfileName", "FriendlyName"})
}

func cleanupNLATree(path string, valueNames []string) {
	key, err := registry.OpenKey(
		registry.LOCAL_MACHINE,
		path,
		registry.ENUMERATE_SUB_KEYS|registry.QUERY_VALUE|registry.WRITE|registry.WOW64_64KEY,
	)
	if err != nil {
		return
	}
	defer key.Close()

	names, err := key.ReadSubKeyNames(-1)
	if err != nil {
		return
	}
	for _, name := range names {
		if !nlaSubKeyMatches(key, name, valueNames) {
			continue
		}
		_ = registry.DeleteKey(key, name)
	}
}

func nlaSubKeyMatches(parent registry.Key, name string, valueNames []string) bool {
	sub, err := registry.OpenKey(parent, name, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return false
	}
	defer sub.Close()
	for _, vn := range valueNames {
		v, _, err := sub.GetStringValue(vn)
		if err != nil {
			continue
		}
		if NLANameMatches(v) {
			return true
		}
	}
	return false
}
