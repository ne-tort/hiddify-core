package config

import (
	"testing"

	"github.com/sagernet/sing-box/option"
)

func TestClashApiSecretNotRandomized(t *testing.T) {
	h := DefaultHiddifyOptions()
	h.EnableClashApi = true
	h.ClashApiPort = 16756
	h.ClashApiSecret = ""
	var options option.Options
	setExperimental(&options, h)
	if options.Experimental == nil || options.Experimental.ClashAPI == nil {
		t.Fatal("expected ClashAPI")
	}
	if options.Experimental.ClashAPI.Secret != "" {
		t.Fatalf("secret should stay empty from client, got %q", options.Experimental.ClashAPI.Secret)
	}
	if h.ClashApiSecret != "" {
		t.Fatalf("hopt secret mutated: %q", h.ClashApiSecret)
	}
}

func TestClashApiSecretPassthrough(t *testing.T) {
	h := DefaultHiddifyOptions()
	h.EnableClashApi = true
	h.ClashApiSecret = "fixed-secret-16"
	var options option.Options
	setExperimental(&options, h)
	if options.Experimental.ClashAPI.Secret != "fixed-secret-16" {
		t.Fatalf("secret=%q", options.Experimental.ClashAPI.Secret)
	}
}
