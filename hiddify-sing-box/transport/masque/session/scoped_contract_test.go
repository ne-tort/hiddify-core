package session

import (
	"encoding/json"
	"os"
	"testing"
)

func TestBuildScopedErrorArtifactNormalizesErrorSource(t *testing.T) {
	tests := []struct {
		name   string
		source string
		want   string
	}{
		{
			name:   "runtime",
			source: ErrorSourceRuntime,
			want:   ErrorSourceRuntime,
		},
		{
			name:   "compose_up",
			source: ErrorSourceComposeUp,
			want:   ErrorSourceComposeUp,
		},
		{
			name:   "empty_fallback_runtime",
			source: "",
			want:   ErrorSourceRuntime,
		},
		{
			name:   "unknown_fallback_runtime",
			source: "docker_boot",
			want:   ErrorSourceRuntime,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			artifact := BuildScopedErrorArtifact(ErrorClassCapability, ErrorClassCapability, tc.source)
			if artifact.ErrorSource != tc.want {
				t.Fatalf("unexpected artifact source: got=%s want=%s", artifact.ErrorSource, tc.want)
			}
		})
	}
}

func TestClassifyMalformedScopedTargetClassPair(t *testing.T) {
	actualClass, resultClass, err := ClassifyMalformedScopedTargetClassPair(ClientOptions{
		Server:               "example.com",
		ServerPort:           443,
		TemplateIP:           "https://example.com/masque/ip/{target}/{ipproto}",
		ConnectIPScopeTarget: "not-a-prefix",
	}, TemplateURIHooks{})
	if err == nil {
		t.Fatal("expected malformed scoped classification helper to fail for invalid target")
	}
	if actualClass != ErrorClassCapability {
		t.Fatalf("expected malformed scope classification capability, got: %s (err=%v)", actualClass, err)
	}
	if resultClass != ErrorClassCapability {
		t.Fatalf("expected wrapped malformed scope classification capability, got: %s (err=%v)", resultClass, err)
	}
	writeMalformedScopedArtifactIfRequested(t, actualClass, resultClass)
}

func writeMalformedScopedArtifactIfRequested(t *testing.T, actualClass, resultClass ErrorClass) {
	t.Helper()

	artifactPath := os.Getenv("MASQUE_MALFORMED_SCOPED_TRANSPORT_ARTIFACT_PATH")
	if artifactPath == "" {
		return
	}
	artifact := BuildScopedErrorArtifact(actualClass, resultClass, "runtime")
	raw, err := json.MarshalIndent(artifact, "", "  ")
	if err != nil {
		t.Fatalf("marshal malformed-scoped artifact: %v", err)
	}
	if err := os.WriteFile(artifactPath, raw, 0o644); err != nil {
		t.Fatalf("write malformed-scoped artifact: %v", err)
	}
}
