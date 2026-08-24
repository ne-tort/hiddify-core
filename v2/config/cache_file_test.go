package config

import (
	"testing"

	"github.com/sagernet/sing-box/option"
)

func TestCacheFileDefaultsEnabled(t *testing.T) {
	h := DefaultClientOptions()
	var options option.Options
	setExperimental(&options, h)
	cf := options.Experimental.CacheFile
	if cf == nil || !cf.Enabled {
		t.Fatal("cache_file should be enabled by default")
	}
	if !cf.StoreFakeIP {
		t.Fatal("store_fakeip should default on")
	}
	if cf.StoreDNS {
		t.Fatal("store_dns should default off")
	}
	if cf.Path != "data/clash.db" {
		t.Fatalf("unexpected path %q", cf.Path)
	}
}

func TestCacheFileDisabled(t *testing.T) {
	h := DefaultClientOptions()
	h.EnableCacheFile = false
	h.CacheFileStoreFakeIP = true
	h.CacheFileStoreDNS = true
	var options option.Options
	setExperimental(&options, h)
	cf := options.Experimental.CacheFile
	if cf == nil {
		t.Fatal("expected cache_file block with enabled=false")
	}
	if cf.Enabled {
		t.Fatal("cache_file must be disabled")
	}
	if cf.StoreFakeIP || cf.StoreDNS {
		t.Fatal("store flags must be off when cache file is disabled")
	}
}

func TestCacheFileTestModeForcesEnable(t *testing.T) {
	h := DefaultClientOptions()
	h.EnableCacheFile = false
	h.TestMode = true
	h.CacheFilePath = "data/test-clash.db"
	var options option.Options
	setExperimental(&options, h)
	cf := options.Experimental.CacheFile
	if cf == nil || !cf.Enabled {
		t.Fatal("TestMode must force cache_file on")
	}
	if cf.Path != "data/test-clash.db" {
		t.Fatalf("unexpected path %q", cf.Path)
	}
}
