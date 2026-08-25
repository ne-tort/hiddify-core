package hcore

import (
	"context"
	"fmt"

	"github.com/ne-tort/pathology-core/compat/monitoring"
	"github.com/ne-tort/pathology-core/v2/config"
	"github.com/ne-tort/pathology-core/v2/db"
	hcommon "github.com/ne-tort/pathology-core/v2/hcommon"
	hutils "github.com/ne-tort/pathology-core/v2/hutils"
)

func (s *CoreService) Stop(ctx context.Context, empty *hcommon.Empty) (*CoreInfoResponse, error) {
	return Stop()
}

func Stop() (coreResponse *CoreInfoResponse, err error) {
	defer config.DeferPanicToError("stop", func(recovered_err error) {
		coreResponse, err = errorWrapper(MessageType_UNEXPECTED_ERROR, recovered_err)
	})

	// if static.CoreState != CoreStates_STARTED {
	// 	return errorWrapper(MessageType_INSTANCE_NOT_STARTED, fmt.Errorf("instance not started"))
	// }
	// if static.Box == nil {
	// 	return errorWrapper(MessageType_INSTANCE_NOT_FOUND, fmt.Errorf("instance not found"))
	// }
	static.lock.Lock()
	defer static.lock.Unlock()

	SetCoreStatus(CoreStates_STOPPING, MessageType_EMPTY, "")
	stopWindowsMemoryScavenge()
	ss := static.StartedService
	if ss == nil {
		monitoring.Deactivate()
		_ = db.CloseAll()
		return SetCoreStatus(CoreStates_STOPPED, MessageType_ALREADY_STOPPED, ""), nil
	}

	monitoring.Deactivate()
	if err := ss.CloseService(); err != nil {
		static.StartedService = nil
		configureMemoryLimit(true) // drop soft GOMEMLIMIT after failed stop
		_ = db.CloseAll()
		dumpGoroutinesToFile(fmt.Sprint(sWorkingPath, "/data/goroutine-stop.log"))
		hutils.HealStickyTun()
		return errorWrapper(MessageType_UNEXPECTED_ERROR, err)
	}
	// err = common.Close(static.StartedService)
	static.StartedService = nil
	configureMemoryLimit(true) // clear soft limit while VPN is down
	_ = db.CloseAll()

	hutils.HealStickyTun()
	return SetCoreStatus(CoreStates_STOPPED, MessageType_EMPTY, ""), nil
}
