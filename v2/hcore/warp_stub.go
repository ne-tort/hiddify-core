package hcore

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// GenerateWarpConfig removed with WARP cleanup; RPC kept for proto compat until proto regen.
func (s *CoreService) GenerateWarpConfig(ctx context.Context, in *GenerateWarpConfigRequest) (*WarpGenerationResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "WARP generation removed (sing-box-lx)")
}
