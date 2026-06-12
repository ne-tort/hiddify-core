package session

import (
	"context"
	"errors"
)

// CoreSessionBuilder constructs a production coreSession (wired from package masque during phase F).
type CoreSessionBuilder func(ctx context.Context, options ClientOptions) (ClientSession, error)

// DirectSessionBuilder constructs the plain-TCP direct backend session.
type DirectSessionBuilder func(ctx context.Context, options ClientOptions) (ClientSession, error)

var (
	// BuildCoreSession is set by transport/masque at init.
	BuildCoreSession CoreSessionBuilder
	// BuildDirectSession is set by transport/masque at init.
	BuildDirectSession DirectSessionBuilder
)

// CoreClientFactory is the production MASQUE client session factory.
type CoreClientFactory struct{}

func (CoreClientFactory) NewSession(ctx context.Context, options ClientOptions) (ClientSession, error) {
	if BuildCoreSession == nil {
		return nil, errors.New("masque: core session builder not wired")
	}
	return BuildCoreSession(ctx, options)
}

// DirectClientFactory is the plain direct-TCP backend (CONNECT-stream / CONNECT-UDP without MASQUE overlay).
type DirectClientFactory struct{}

func (DirectClientFactory) NewSession(ctx context.Context, options ClientOptions) (ClientSession, error) {
	if BuildDirectSession == nil {
		return nil, errors.New("masque: direct session builder not wired")
	}
	return BuildDirectSession(ctx, options)
}
