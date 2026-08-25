package hcore

import (
	"fmt"
	"runtime"
	"runtime/debug"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/experimental/libbox"
)

// Desktop soft memory target (GOMEMLIMIT-style). libbox applies SetMemoryLimit(limit*3/4).
const desktopOOMMemoryLimit = 512 * 1024 * 1024 // 512 MiB

var (
	oomKillerEnabled  bool
	oomKillerDisabled bool
	oomMemoryLimit    uint64
)

// configureMemoryLimit wires libbox soft memory limit + OOM killer service options
// used by newService. When disabled, clears the Go memory limit.
func configureMemoryLimit(disableMemoryLimit bool) {
	enabled := !disableMemoryLimit
	var limit int64
	if enabled {
		if C.IsIos {
			// libbox.ReloadSetupOptions fills DefaultAppleNetworkExtensionMemoryLimit when 0.
			limit = 0
		} else {
			limit = desktopOOMMemoryLimit
		}
	}
	// KillerDisabled=true: FreeOSMemory on pressure without ResetNetwork (desktop soft target).
	libbox.ReloadSetupOptions(&libbox.SetupOptions{
		OomKillerEnabled:  enabled,
		OomKillerDisabled: true,
		OomMemoryLimit:    limit,
	})
	oomKillerEnabled = enabled
	oomKillerDisabled = true
	if !enabled {
		oomMemoryLimit = 0
		return
	}
	if limit > 0 {
		oomMemoryLimit = uint64(limit)
	} else {
		oomMemoryLimit = 50 * 1024 * 1024 // Apple NE default (service also resolves via override 0)
	}
}

func logMemoryStats(prefix string) {
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	Log(LogLevel_DEBUG, LogType_CORE, fmt.Sprintf(
		"%s HeapSys=%s HeapInuse=%s HeapIdle=%s HeapReleased=%s Sys=%s",
		prefix,
		formatMemBytes(ms.HeapSys),
		formatMemBytes(ms.HeapInuse),
		formatMemBytes(ms.HeapIdle),
		formatMemBytes(ms.HeapReleased),
		formatMemBytes(ms.Sys),
	))
}

func formatMemBytes(n uint64) string {
	return fmt.Sprintf("%d", n)
}

func freeOSMemoryNow() {
	debug.FreeOSMemory()
}
