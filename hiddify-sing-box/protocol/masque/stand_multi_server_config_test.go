package masque

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/sagernet/sing-box/option"
)

// findRepoFile walks parents from cwd until relPath exists (relPath uses / separators).
func findRepoFile(t *testing.T, relPath string) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	rel := filepath.FromSlash(relPath)
	for i := 0; i < 14; i++ {
		candidate := filepath.Join(dir, rel)
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Fatalf("repo file not found: %s", relPath)
	return ""
}

func findMasqueServerMultiStandConfig(t *testing.T) string {
	return findRepoFile(t, "experiments/router/stand/l3router/configs/masque-server-multi.json")
}

func TestMasqueServerMultiStandJSONValidates(t *testing.T) {
	path := findMasqueServerMultiStandConfig(t)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Endpoints []json.RawMessage `json:"endpoints"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	seenTag := make(map[string]struct{})
	seenPort := make(map[uint16]struct{})
	for i, raw := range doc.Endpoints {
		var head struct {
			Type string `json:"type"`
			Tag  string `json:"tag"`
		}
		if err := json.Unmarshal(raw, &head); err != nil {
			t.Fatalf("endpoint[%d] head: %v", i, err)
		}
		if head.Type != "masque" {
			continue
		}
		if _, dup := seenTag[head.Tag]; dup {
			t.Fatalf("duplicate tag %q", head.Tag)
		}
		seenTag[head.Tag] = struct{}{}
		var o option.MasqueEndpointOptions
		if err := json.Unmarshal(raw, &o); err != nil {
			t.Fatalf("endpoint[%d] %s options: %v", i, head.Tag, err)
		}
		if _, dup := seenPort[o.ListenPort]; dup {
			t.Fatalf("duplicate listen_port %d (tags %q)", o.ListenPort, head.Tag)
		}
		seenPort[o.ListenPort] = struct{}{}
		if err := validateMasqueOptions(o); err != nil {
			t.Fatalf("validate %s: %v", head.Tag, err)
		}
	}
	if len(seenPort) < 4 {
		t.Fatalf("expected at least 4 masque server endpoints with distinct listen_port, got %d", len(seenPort))
	}
}

func TestMasqueServerMultiVpsJSONValidates(t *testing.T) {
	path := findRepoFile(t, "experiments/router/stand/l3router/configs/masque-server-multi-vps.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Endpoints []json.RawMessage `json:"endpoints"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	seenTag := make(map[string]struct{})
	seenPort := make(map[uint16]struct{})
	for i, raw := range doc.Endpoints {
		var head struct {
			Type string `json:"type"`
			Tag  string `json:"tag"`
		}
		if err := json.Unmarshal(raw, &head); err != nil {
			t.Fatalf("endpoint[%d] head: %v", i, err)
		}
		if head.Type != "masque" {
			continue
		}
		if _, dup := seenTag[head.Tag]; dup {
			t.Fatalf("duplicate tag %q", head.Tag)
		}
		seenTag[head.Tag] = struct{}{}
		var o option.MasqueEndpointOptions
		if err := json.Unmarshal(raw, &o); err != nil {
			t.Fatalf("endpoint[%d] %s options: %v", i, head.Tag, err)
		}
		if o.ListenPort == 0 {
			t.Fatalf("expected server endpoint %s to set listen_port", head.Tag)
		}
		if _, dup := seenPort[o.ListenPort]; dup {
			t.Fatalf("duplicate listen_port %d (tags %q)", o.ListenPort, head.Tag)
		}
		seenPort[o.ListenPort] = struct{}{}
		if err := validateMasqueOptions(o); err != nil {
			t.Fatalf("validate %s: %v", head.Tag, err)
		}
	}
	if len(seenPort) < 10 {
		t.Fatalf("expected at least 10 masque server endpoints, got %d", len(seenPort))
	}
}

func TestMasqueMultiVpsClientJSONValidates(t *testing.T) {
	path := findRepoFile(t, "scripts/examples/masque_multi_vps_client.all-endpoints.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Endpoints []json.RawMessage `json:"endpoints"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	seenTag := make(map[string]struct{})
	for i, raw := range doc.Endpoints {
		var head struct {
			Type string `json:"type"`
			Tag  string `json:"tag"`
		}
		if err := json.Unmarshal(raw, &head); err != nil {
			t.Fatalf("endpoint[%d] head: %v", i, err)
		}
		if head.Type != "masque" {
			continue
		}
		if _, dup := seenTag[head.Tag]; dup {
			t.Fatalf("duplicate tag %q", head.Tag)
		}
		seenTag[head.Tag] = struct{}{}
		var o option.MasqueEndpointOptions
		if err := json.Unmarshal(raw, &o); err != nil {
			t.Fatalf("endpoint[%d] %s options: %v", i, head.Tag, err)
		}
		if err := validateMasqueOptions(o); err != nil {
			t.Fatalf("validate %s: %v", head.Tag, err)
		}
	}
	if len(seenTag) < 50 {
		t.Fatalf("expected many client masque endpoints, got %d", len(seenTag))
	}
}
