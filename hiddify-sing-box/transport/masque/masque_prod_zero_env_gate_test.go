package masque

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

var masqueProdForbiddenEnv = regexp.MustCompile(`os\.(Getenv|LookupEnv)\(`)

func TestGATEMasqueProdZeroEnvProtocolEndpoint(t *testing.T) {
	t.Parallel()
	protoDir := filepath.Join("..", "..", "protocol", "masque")
	path := filepath.Join(protoDir, "endpoint.go")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if masqueProdForbiddenEnv.Match(data) {
		t.Fatalf("protocol/masque/endpoint.go must not use getenv in prod path")
	}
	for _, name := range []string{"endpoint_client.go", "endpoint_server.go", "endpoint_warp_masque.go"} {
		p := filepath.Join(protoDir, name)
		data, err := os.ReadFile(p)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			t.Fatal(err)
		}
		if masqueProdForbiddenEnv.Match(data) {
			t.Fatalf("%s must not use getenv in prod path", name)
		}
	}
}

func TestGATEMasqueDockerBenchConnectUDPMatrixZeroEnv(t *testing.T) {
	t.Parallel()
	matrix := readDockerBenchSource(t, "connect_udp_matrix.py")
	forbidden := []string{
		"MASQUE_H2_",
		"MASQUE_CONNECT_STREAM_PIPE_UPLOAD",
		"MASQUE_CONNECT_IP_",
		"HIDDIFY_",
		"MASQUE_CONNECT_UDP_",
	}
	for _, key := range forbidden {
		if strings.Contains(matrix, key) {
			t.Fatalf("connect_udp_matrix.py: forbidden perf env %q (use LocalProfile fields)", key)
		}
	}
	requireSubstrings(t, matrix, "connect-udp matrix zero-env",
		"pipe_upload",
		"LocalProfile",
	)
}
