package masque

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

var connectStreamProdForbiddenEnv = regexp.MustCompile(`os\.(Getenv|LookupEnv)\(`)

var connectStreamProdZeroEnvDirs = []string{"stream", "h2", "h3", "session"}

var connectStreamXNetMasqueGlob = filepath.Join("..", "..", "replace", "x-net-patched", "http2", "masque_*.go")

var connectStreamHTTP3ClientPath = filepath.Join("..", "..", "replace", "quic-go-patched", "http3", "client.go")

func TestGATEConnectStreamProdZeroEnv(t *testing.T) {
	t.Parallel()
	for _, rel := range connectStreamProdZeroEnvDirs {
		scanConnectStreamProdNoGetenv(t, rel)
	}
	matches, err := filepath.Glob(connectStreamXNetMasqueGlob)
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) == 0 {
		t.Fatal("no x-net masque_*.go sources found")
	}
	for _, path := range matches {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if connectStreamProdForbiddenEnv.Match(data) {
			t.Fatalf("%s: os.Getenv in x-net masque patch", path)
		}
	}
	http3Client, err := os.ReadFile(connectStreamHTTP3ClientPath)
	if err != nil {
		t.Fatal(err)
	}
	if connectStreamProdForbiddenEnv.Match(http3Client) {
		t.Fatalf("%s: os.Getenv in http3 CONNECT client", connectStreamHTTP3ClientPath)
	}
}

func TestGATEConnectStreamProdNoExperimentalQUICMerge(t *testing.T) {
	t.Parallel()
	forbidden := []string{
		"ApplyQUICExperimentalOptions",
		"QUICExperimentalOptions",
		"QUICExperimental:",
	}
	roots := []string{"session", "stream", "h3", "h2"}
	for _, root := range roots {
		err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			src := string(data)
			for _, needle := range forbidden {
				if strings.Contains(src, needle) {
					t.Errorf("%s: forbidden experimental QUIC symbol %q", path, needle)
				}
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", root, err)
		}
	}
}

func scanConnectStreamProdNoGetenv(t *testing.T, root string) {
	t.Helper()
	var violations []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		if strings.Contains(path, string(filepath.Separator)+"inttest"+string(filepath.Separator)) {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if connectStreamProdForbiddenEnv.Match(data) {
			violations = append(violations, path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}
	if len(violations) > 0 {
		t.Fatalf("%s prod sources must not use getenv: %v", root, violations)
	}
}

func TestGATEConnectStreamProdZeroEnvMasqueRoot(t *testing.T) {
	t.Parallel()
	matches, err := filepath.Glob("connect_stream_*.go")
	if err != nil {
		t.Fatal(err)
	}
	var violations []string
	for _, path := range matches {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		if strings.Contains(path, "harness") || strings.Contains(path, "bench_harness") {
			continue
		}
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if connectStreamProdForbiddenEnv.Match(data) {
			violations = append(violations, path)
		}
	}
	if len(violations) > 0 {
		t.Fatalf("masque connect_stream_* prod sources must not use getenv: %v", violations)
	}
}

func TestGATEMasqueDockerBenchConnectStreamLocalProfilesZeroEnv(t *testing.T) {
	t.Parallel()
	local := readDockerBenchSource(t, "local_profiles.py")
	forbidden := []string{
		"MASQUE_H2_",
		"MASQUE_CONNECT_STREAM_",
		"MASQUE_H3_",
		"MASQUE_BISECT_",
		"HIDDIFY_",
		"MASQUE_RELAY_",
	}
	for _, key := range forbidden {
		if strings.Contains(local, key) {
			t.Fatalf("local_profiles.py: forbidden perf env %q", key)
		}
	}
	requireSubstrings(t, local, "connect-stream zero-env client",
		`name="connect-stream-h3"`,
		`name="connect-stream-h2"`,
		`tcp_transport="connect_stream"`,
		`MASQUE_BENCH_SKIP_URL_TEST`,
		"Transport perf knobs are hardcoded in sing-box",
	)
}
