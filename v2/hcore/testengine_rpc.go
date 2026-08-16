package hcore

import (
	"context"

	"github.com/ne-tort/pathology-core/v2/hcore/testengine"
)

func (s *CoreService) TestEngineEnsure(ctx context.Context, in *TestEngineEnsureRequest) (*TestEngineEnsureResponse, error) {
	res, err := testengine.Global().Ensure(ctx, in.GetProfileId(), in.GetProfileConfigPath(), in.GetOutboundTags())
	if err != nil {
		return nil, err
	}
	return &TestEngineEnsureResponse{
		MixedPort: uint32(res.MixedPort),
		ProfileId: res.ProfileID,
	}, nil
}

func (s *CoreService) TestEngineStop(ctx context.Context, in *TestEngineStopRequest) (*TestEngineStopResponse, error) {
	_ = in
	if err := testengine.Global().Stop(ctx); err != nil {
		return nil, err
	}
	return &TestEngineStopResponse{}, nil
}

func (s *CoreService) TestEnginePing(ctx context.Context, in *TestEnginePingRequest) (*TestEnginePingResponse, error) {
	results, err := testengine.Global().Ping(ctx, in.GetProfileId(), in.GetOutboundTag(), in.GetStrategy(), in.GetTestUrl())
	if err != nil {
		return nil, err
	}
	out := &TestEnginePingResponse{}
	for _, r := range results {
		out.Results = append(out.Results, &TestEnginePingResult{
			Tag:          r.Tag,
			DelayMs:      r.DelayMs,
			Failed:       r.Failed,
			FailRate:     r.FailRate,
			Samples:      r.Samples,
			SamplesOk:    r.SamplesOK,
			ErrorMessage: r.ErrorMessage,
		})
	}
	return out, nil
}
