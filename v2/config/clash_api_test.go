package config

import (
	"testing"

	"github.com/sagernet/sing-box/option"
)

func TestClashApiNeverEmitted(t *testing.T) {
	h := DefaultClientOptions()
	h.EnableClashApi = true
	h.ClashApiPort = 16756
	h.ClashApiSecret = "fixed-secret-16"
	var options option.Options
	setExperimental(&options, h)
	if options.Experimental == nil {
		t.Fatal("expected experimental cache block")
	}
	if options.Experimental.ClashAPI != nil {
		t.Fatal("ClashAPI must not be emitted (with_clash_api retired)")
	}
}
