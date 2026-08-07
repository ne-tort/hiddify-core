package config

import (
	context "context"
	"fmt"
	"path/filepath"
	"runtime/debug"
	"time"

	"github.com/ne-tort/pathology-core/v2/hutils"
	"github.com/sagernet/sing-box/option"
)

func SaveCurrentConfig(ctx context.Context, path string, options option.Options) error {
	json, err := options.MarshalJSONContext(ctx)
	if err != nil {
		return err
	}
	p, err := filepath.Abs(path)
	fmt.Printf("Saving config to %v %+v\n", p, err)
	if err != nil {
		return err
	}
	return hutils.WriteFileAtomic(p, []byte(json), 0o644)
}

func DeferPanicToError(name string, err func(error)) {
	if r := recover(); r != nil {
		s := fmt.Errorf("%s panic: %s\n%s", name, r, string(debug.Stack()))
		err(s)
		<-time.After(5 * time.Second)
	}
}
