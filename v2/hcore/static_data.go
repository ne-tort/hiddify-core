package hcore

import (
	"context"
	"sync"
	"time"

	"github.com/ne-tort/pathology-core/v2/config"
	"github.com/ne-tort/pathology-core/compat/monitoring"
	"github.com/sagernet/sing-box/daemon"
	"github.com/sagernet/sing-box/experimental/libbox"
	"github.com/sagernet/sing-box/log"
)

type PathologyInstance struct {
	StartedService *daemon.StartedService
	ClientOptions *config.ClientOptions
	// activeConfigPath string
	CoreLogFactory            log.Factory
	coreInfoObserver          *monitoring.Broadcaster[*CoreInfoResponse]
	CoreState                 CoreStates
	logObserver               *monitoring.Broadcaster[*LogMessage]
	systemInfoObserver        *monitoring.Broadcaster[*SystemInfo]
	outboundsInfoObserver     *monitoring.Broadcaster[*OutboundGroupList]
	mainOutboundsInfoObserver *monitoring.Broadcaster[*OutboundGroupList]
	lock                      sync.Mutex
	globalPlatformInterface   libbox.PlatformInterface
	previousStartRequest      *StartRequest
	debug                     bool
	ListenPort                uint16
	BaseContext               context.Context
	endPauseTimer             *time.Timer // only for ios

	logLevel LogLevel
}

var static = &PathologyInstance{
	CoreState:                 CoreStates_STOPPED,
	coreInfoObserver:          monitoring.NewBroadcaster[*CoreInfoResponse](context.Background()),
	logObserver:               monitoring.NewBroadcaster[*LogMessage](context.Background()),
	systemInfoObserver:        monitoring.NewBroadcaster[*SystemInfo](context.Background()),
	outboundsInfoObserver:     monitoring.NewBroadcaster[*OutboundGroupList](context.Background()),
	mainOutboundsInfoObserver: monitoring.NewBroadcaster[*OutboundGroupList](context.Background()),
}
