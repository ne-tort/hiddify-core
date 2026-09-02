package hcore

import (
	"context"
	"fmt"

	"github.com/ne-tort/pathology-core/v2/db"
	hcommon "github.com/ne-tort/pathology-core/v2/hcommon"
	"github.com/ne-tort/pathology-core/v2/hcore/session"
)

var sessionWorkingDir string

// SessionInit stores paths after Setup.
func SessionInit(wd string) {
	sessionWorkingDir = wd
}

// SessionConnect runs the unified headless connect pipeline.
func SessionConnect(ctx context.Context) (*CoreInfoResponse, error) {
	st := session.LoadState()
	if err := sessionApplyClientSettings(); err != nil {
		return nil, fmt.Errorf("apply client settings: %w", err)
	}
	target, err := session.ResolveStartTarget(st, sessionWorkingDir)
	if err != nil {
		return SetCoreStatus(CoreStates_STOPPED, MessageType_ERROR_BUILDING_CONFIG, err.Error()), nil
	}
	req := &StartRequest{
		ConfigPath:         target.Path,
		ConfigName:         target.Name,
		DisableMemoryLimit: st.DisableMemoryLimit,
	}
	resp, err := StartService(ctx, req)
	if err != nil {
		return resp, err
	}
	if resp != nil && resp.MessageType == MessageType_EMPTY {
		_ = session.SaveState(session.State{
			ActiveProfileIDs:   st.ActiveProfileIDs,
			DirectMode:         st.DirectMode,
			ServiceMode:        st.ServiceMode,
			Profiles:           st.Profiles,
			StartTarget:        &target,
			DisableMemoryLimit: st.DisableMemoryLimit,
		})
	}
	return resp, err
}

// SessionDisconnect stops VPN.
func SessionDisconnect(ctx context.Context) (*CoreInfoResponse, error) {
	return Stop()
}

// SessionReconnect stops and restarts with resolved target.
func SessionReconnect(ctx context.Context) (*CoreInfoResponse, error) {
	st := session.LoadState()
	if err := sessionApplyClientSettings(); err != nil {
		return nil, fmt.Errorf("apply client settings: %w", err)
	}
	target, err := session.ResolveStartTarget(st, sessionWorkingDir)
	if err != nil {
		return SetCoreStatus(CoreStates_STOPPED, MessageType_ERROR_BUILDING_CONFIG, err.Error()), nil
	}
	req := &StartRequest{
		ConfigPath:         target.Path,
		ConfigName:         target.Name,
		DisableMemoryLimit: st.DisableMemoryLimit,
		DelayStart:         true,
	}
	return Restart(ctx, req)
}

// SessionGetState returns session snapshot from LevelDB.
func SessionGetState() session.State {
	return session.LoadState()
}

// SessionClearUiPid drops the stored UI pid after UI exit.
func SessionClearUiPid() error {
	return session.ClearUiPid()
}

// SessionClearUiPidIf drops ui_pid only when it still matches the exiting UI process.
func SessionClearUiPidIf(expected int32) error {
	return session.ClearUiPidIf(expected)
}

func sessionApplyClientSettings() error {
	settings := db.GetTable[hcommon.AppSettings]()
	val, err := settings.Get("ClientSettingsJson")
	if err != nil || val == nil {
		return nil
	}
	jsonStr, ok := val.Value.(string)
	if !ok || jsonStr == "" {
		return nil
	}
	_, err = ChangeClientSettings(&ChangeClientSettingsRequest{ClientSettingsJson: jsonStr}, false)
	return err
}

// SessionLastErrorMessage formats a CoreInfoResponse for tray tooltip/logging.
func SessionLastErrorMessage(resp *CoreInfoResponse, err error) string {
	if err != nil {
		return err.Error()
	}
	if resp == nil {
		return "unknown error"
	}
	if resp.MessageType == MessageType_EMPTY {
		return ""
	}
	return fmt.Sprintf("%s: %s", resp.MessageType.String(), resp.Message)
}
