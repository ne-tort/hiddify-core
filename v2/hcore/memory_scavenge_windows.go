//go:build windows

package hcore

import (
	"sync"
	"time"
)

const windowsMemoryScavengeInterval = 5 * time.Minute

var (
	scavengeMu   sync.Mutex
	scavengeStop chan struct{}
)

// startWindowsMemoryScavenge periodically returns idle spans to the OS while VPN is up.
func startWindowsMemoryScavenge() {
	stopWindowsMemoryScavenge()
	scavengeMu.Lock()
	defer scavengeMu.Unlock()
	stopCh := make(chan struct{})
	scavengeStop = stopCh
	go func() {
		ticker := time.NewTicker(windowsMemoryScavengeInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				freeOSMemoryNow()
				if static.debug {
					logMemoryStats("windows FreeOSMemory")
				}
			case <-stopCh:
				return
			}
		}
	}()
}

func stopWindowsMemoryScavenge() {
	scavengeMu.Lock()
	defer scavengeMu.Unlock()
	if scavengeStop != nil {
		close(scavengeStop)
		scavengeStop = nil
	}
}
