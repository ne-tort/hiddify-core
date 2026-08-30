package hcore

import (
	"context"

	"github.com/ne-tort/pathology-core/v2/hcommon"
	"github.com/ne-tort/pathology-core/v2/hcore/session"
)

func (s *CoreService) SessionConnect(ctx context.Context, _ *hcommon.Empty) (*CoreInfoResponse, error) {
	return SessionConnect(ctx)
}

func (s *CoreService) SessionDisconnect(ctx context.Context, _ *hcommon.Empty) (*CoreInfoResponse, error) {
	return SessionDisconnect(ctx)
}

func (s *CoreService) SessionReconnect(ctx context.Context, _ *hcommon.Empty) (*CoreInfoResponse, error) {
	return SessionReconnect(ctx)
}

func (s *CoreService) GetSessionState(ctx context.Context, _ *hcommon.Empty) (*SessionState, error) {
	return toProtoSessionState(SessionGetState()), nil
}

func (s *CoreService) SetActiveProfiles(ctx context.Context, in *SetActiveProfilesRequest) (*SessionState, error) {
	st, err := session.SetActiveProfiles(in.GetProfileIds())
	if err != nil {
		return nil, err
	}
	return toProtoSessionState(st), nil
}

func (s *CoreService) SetServiceMode(ctx context.Context, in *SetServiceModeRequest) (*SessionState, error) {
	st, err := SessionSetServiceMode(in.GetServiceMode())
	if err != nil {
		return nil, err
	}
	return toProtoSessionState(st), nil
}

func (s *CoreService) SyncSessionState(ctx context.Context, in *SyncSessionStateRequest) (*SessionState, error) {
	if in == nil {
		return toProtoSessionState(session.LoadState()), nil
	}
	if in.GetClearUiPid() {
		_ = session.ClearUiPid()
	}
	if in.GetState() == nil {
		notifyTrayDisplaySync()
		return toProtoSessionState(session.LoadState()), nil
	}
	st, err := session.SyncState(fromProtoSessionState(in.GetState()))
	if err != nil {
		return nil, err
	}
	notifyTrayDisplaySync()
	return toProtoSessionState(st), nil
}

func toProtoSessionState(st session.State) *SessionState {
	out := &SessionState{
		ActiveProfileIds:   st.ActiveProfileIDs,
		DirectMode:         st.DirectMode,
		ServiceMode:        st.ServiceMode,
		DisableMemoryLimit: st.DisableMemoryLimit,
		CoreState:          CurrentCoreState(),
		Locale:             st.Locale,
		ThemeMode:          st.ThemeMode,
		UiPid:              st.UiPid,
	}
	for _, p := range st.Profiles {
		out.Profiles = append(out.Profiles, &SessionProfileMeta{
			Id:     p.ID,
			Name:   p.Name,
			Active: p.Active,
		})
	}
	if st.StartTarget != nil {
		out.StartTarget = &SessionStartTarget{
			Path: st.StartTarget.Path,
			Name: st.StartTarget.Name,
		}
	}
	return out
}

func fromProtoSessionState(in *SessionState) session.State {
	st := session.State{
		ActiveProfileIDs:   in.GetActiveProfileIds(),
		DirectMode:         in.GetDirectMode(),
		ServiceMode:        in.GetServiceMode(),
		DisableMemoryLimit: in.GetDisableMemoryLimit(),
		Locale:             in.GetLocale(),
		ThemeMode:          in.GetThemeMode(),
		UiPid:              in.GetUiPid(),
	}
	for _, p := range in.GetProfiles() {
		st.Profiles = append(st.Profiles, session.ProfileMeta{
			ID:     p.GetId(),
			Name:   p.GetName(),
			Active: p.GetActive(),
		})
	}
	if t := in.GetStartTarget(); t != nil && t.GetPath() != "" {
		st.StartTarget = &session.StartTarget{Path: t.GetPath(), Name: t.GetName()}
	}
	return st
}
