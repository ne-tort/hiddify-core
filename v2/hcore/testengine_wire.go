package hcore

import (
	"github.com/ne-tort/pathology-core/v2/config"
	"github.com/ne-tort/pathology-core/v2/hcore/testengine"
)

func configureTestEngine() {
	testengine.Configure(testengine.Deps{
		BaseContext: static.BaseContext,
		Platform:    static.globalPlatformInterface,
		WorkingDir:  sWorkingPath,
		CloneOptions: func() (*config.ClientOptions, error) {
			return config.CloneClientOptions(static.ClientOptions)
		},
		StartSide: NewSideService,
	})
}
