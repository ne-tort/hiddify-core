package masque

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/transport/masque/connectudp"
)

// Docker bench KPI defaults — keep in sync with docker/masque-perf-lab/run_local.py.
const (
	dockerBenchNetemDelayMS        = 35
	dockerBenchUDPMinRxRatio       = 0.95
	dockerBenchUDPMaxLossPct       = 5.0
	dockerBenchUDPTargetMbit       = 8.0
	dockerBenchUDPMinUpMbit        = 6.0  // paced floor (bench-history 2026-05-19: ~6.66–6.75)
	dockerBenchUDPReproUpTolerance = 0.1  // paced udp_up spread across 3× runs
	dockerBenchConnectStreamSoftMin       = 4.0  // localize floor; soft WARN only (bidi asymmetry expected)
	dockerBenchConnectStreamMinDownMbit   = 21.0 // run_local.py BENCH_CONNECT_STREAM_MIN_DOWN_MBIT (connect-stream-h3)
	dockerBenchConnectStreamVPSKPITarget  = 21.0 // field invoke.py BENCH_KPI_DOWN_MBIT (Q7 wave 2)
	dockerBenchConnectIPMinUpMbit        = 80.0  // run_local.py BENCH_CONNECT_IP_MIN_UP_MBIT
	dockerBenchConnectIPMinDownMbit      = 350.0 // run_local.py BENCH_CONNECT_IP_MIN_DOWN_MBIT
	dockerBenchConnectUDPSoftMinDown  = 50.0 // tcp_down floor @ netem 35 ms (baseline ~60–119)
	dockerBenchConnectUDPSoftMaxRatio = 8.0  // up/down informational asymmetry band
)

func readDockerBenchSource(t *testing.T, name string) string {
	t.Helper()
	root := findDockerPerfLabRoot(t)
	path := filepath.Join(root, name)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(data)
}

func findDockerPerfLabRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	dir := wd
	for range 10 {
		root := filepath.Join(dir, "docker", "masque-perf-lab")
		if _, err := os.Stat(filepath.Join(root, "run_local.py")); err == nil {
			return root
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Skip("docker/masque-perf-lab not found (run from hiddify-app checkout)")
	return ""
}

func findRepoRootFromPerfLab(t *testing.T) string {
	t.Helper()
	lab := findDockerPerfLabRoot(t)
	return filepath.Dir(filepath.Dir(lab))
}

func readRepoSource(t *testing.T, rel string) string {
	t.Helper()
	path := filepath.Join(findRepoRootFromPerfLab(t), rel)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(data)
}

func requireSubstrings(t *testing.T, src, label string, parts ...string) {
	t.Helper()
	for _, part := range parts {
		if !strings.Contains(src, part) {
			t.Fatalf("%s: missing %q in docker bench source", label, part)
		}
	}
}

// TestMasqueDockerBenchRecycleContract locks run_local.py upload→restart server→download
// acceptance (workaround until same-route recycle is default — see sui parity Go tests).
func TestMasqueDockerBenchRecycleContract(t *testing.T) {
	t.Parallel()
	src := readDockerBenchSource(t, "run_local.py")
	requireSubstrings(t, src, "recycle",
		`transport_mode == "connect_ip"`,
		`["restart", "masque-server-core"]`,
		`restart_client(profile)`,
		`wait_connect_ip_tcp_ready`,
		`time.sleep(2)`,
		`iperf_direct_in_client(True`,
		`[bench] upload OK`,
		`[bench] download OK`,
	)
	if !strings.Contains(src, "recycle race") {
		t.Fatal("recycle: expected double TCP probe comment for forwarder-ready race")
	}
}

// TestMasqueDockerBenchNetemTopologyContract documents eth0 (MASQUE client path) vs eth1 (direct backend).
func TestMasqueDockerBenchNetemTopologyContract(t *testing.T) {
	t.Parallel()
	src := readDockerBenchSource(t, "run_local.py")
	requireSubstrings(t, src, "netem direct",
		`def apply_netem_direct`,
		`"eth1"`,
		`apply_netem_iface(SERVER, "eth1"`,
	)
	requireSubstrings(t, src, "netem masque",
		`def apply_netem_masque`,
		`"eth0"`,
		`apply_netem_iface(SERVER, "eth0"`,
	)
	if dockerBenchNetemDelayMS != 35 {
		t.Fatalf("dockerBenchNetemDelayMS=%d want 35", dockerBenchNetemDelayMS)
	}
	if !strings.Contains(src, `BENCH_NETEM_DELAY_MS", "35"`) {
		t.Fatal("run_local.py default BENCH_NETEM_DELAY_MS must stay 35")
	}
}

// TestMasqueDockerBenchUDPProbeContract locks paced KPI gate, BENCH_UDP_MODE policy, rx/sent ratio.
func TestMasqueDockerBenchUDPProbeContract(t *testing.T) {
	t.Parallel()
	runLocal := readDockerBenchSource(t, "run_local.py")
	analyze := readDockerBenchSource(t, filepath.Join("bench", "udp_sink_analyze.py"))

	requireSubstrings(t, runLocal, "udp mode",
		`BENCH_UDP_MODE`, `"paced"`, `"max"`, `"both"`,
		`unknown BENCH_UDP_MODE`,
		`KPI gate (udp_deliv) applies only to **paced**`,
	)
	requireSubstrings(t, runLocal, "udp rx/sent",
		`UDP_MIN_RX_RATIO`, `"0.95"`,
		`ratio < UDP_MIN_RX_RATIO`,
		`UDP_MAX_LOSS_PCT`, `"5.0"`,
	)
	requireSubstrings(t, runLocal, "udp seq/hash table",
		`_udp_analyze_sink`,
		`udp_sink_analyze.py`,
		`fill_sha256`,
		`RESULT_UDP_RUN_ID`,
	)
	requireSubstrings(t, analyze, "udp analyze",
		`seq u64 + run_id u32`,
		`RESULT_UDP_FILL_SHA256`,
		`RESULT_UDP_LOSS_PCT`,
		`RESULT_UDP_DUP_PCT`,
	)

	if dockerBenchUDPMinRxRatio != 0.95 {
		t.Fatalf("dockerBenchUDPMinRxRatio=%v want 0.95", dockerBenchUDPMinRxRatio)
	}
	if dockerBenchUDPMaxLossPct != 5.0 {
		t.Fatalf("dockerBenchUDPMaxLossPct=%v want 5.0", dockerBenchUDPMaxLossPct)
	}
	if dockerBenchUDPTargetMbit != 8.0 {
		t.Fatalf("dockerBenchUDPTargetMbit=%v want 8.0", dockerBenchUDPTargetMbit)
	}
	if dockerBenchUDPMinUpMbit != 6.0 {
		t.Fatalf("dockerBenchUDPMinUpMbit=%v want 6.0", dockerBenchUDPMinUpMbit)
	}
	if dockerBenchUDPReproUpTolerance != 0.1 {
		t.Fatalf("dockerBenchUDPReproUpTolerance=%v want 0.1", dockerBenchUDPReproUpTolerance)
	}
	requireSubstrings(t, runLocal, "udp paced kpi",
		`UDP_MIN_UP_MBIT`, `"6.0"`,
		`UDP_REPRO_UP_TOLERANCE`, `"0.1"`,
		`BENCH_UDP_REPRO_RUNS`,
		`paced_up < UDP_MIN_UP_MBIT`,
		`3× repro spread`,
		`repro spread`,
	)
	matrixDoc := readRepoSource(t, filepath.Join("docs", "masque", "benchmark-matrix.md"))
	requireSubstrings(t, matrixDoc, "benchmark-matrix",
		"`connect-ip-h3-tun`",
		"только local",
		"±0.1",
		"`connect-udp-h3`",
		"`connect-udp-h2`",
	)
}

// TestMasqueDockerBenchBenchmarkMatrixContract locks remote Benchmark-Masque.ps1 vs local_profiles.py mapping.
// connect-ip-h3-tun is local-only (packet-plane TUN); remote connect-ip-h3 is hybrid CONNECT-stream.
func TestMasqueDockerBenchBenchmarkMatrixContract(t *testing.T) {
	t.Parallel()
	remote := readRepoSource(t, filepath.Join("scripts", "Benchmark-Masque.ps1"))
	local := readDockerBenchSource(t, "local_profiles.py")
	matrixDoc := readRepoSource(t, filepath.Join("docs", "masque", "benchmark-matrix.md"))

	remoteIDs := []string{"h3", "h2", "connect-ip-h3", "connect-ip-h2"}
	for _, id := range remoteIDs {
		if !strings.Contains(remote, `id = "`+id+`"`) {
			t.Fatalf("Benchmark-Masque.ps1: missing remote profile %q", id)
		}
	}
	if strings.Contains(remote, "connect-ip-h3-tun") {
		t.Fatal("Benchmark-Masque.ps1 must not include connect-ip-h3-tun (local TUN KPI only)")
	}

	localNames := regexp.MustCompile(`name="([^"]+)"`).FindAllStringSubmatch(local, -1)
	byName := map[string]bool{}
	for _, m := range localNames {
		byName[m[1]] = true
	}
	pairs := []struct{ remote, local string }{
		{"h3", "connect-udp-h3"},
		{"h2", "connect-udp-h2"},
		{"connect-ip-h3", "connect-ip-h3"},
		{"connect-ip-h2", "connect-ip-h2"},
	}
	for _, p := range pairs {
		if !byName[p.local] {
			t.Fatalf("local_profiles.py: missing local counterpart %q for remote %q", p.local, p.remote)
		}
		requireSubstrings(t, matrixDoc, "matrix map "+p.remote,
			"`"+p.remote+"`",
			"`"+p.local+"`",
		)
	}
	if !byName["connect-ip-h3-tun"] {
		t.Fatal("local_profiles.py: missing connect-ip-h3-tun (local P0 KPI)")
	}
	requireSubstrings(t, local, "connect-ip-h3-tun tun",
		`name="connect-ip-h3-tun"`,
		`tcp_transport="connect_ip"`,
		`via="tun"`,
	)
	requireSubstrings(t, matrixDoc, "connect-ip gap",
		"не включает",
		"`connect-ip-h3-tun`",
		"hybrid",
	)
}

// TestMasqueDockerBenchConnectStreamSoftKPIContract locks informational soft gate for bidi asymmetry.
// connect-stream profiles never hard-fail on up>>down; only WARN below localize floor 4 Mbit/s.
func TestMasqueDockerBenchConnectStreamSoftKPIContract(t *testing.T) {
	t.Parallel()
	runLocal := readDockerBenchSource(t, "run_local.py")
	matrixDoc := readRepoSource(t, filepath.Join("docs", "masque", "benchmark-matrix.md"))

	requireSubstrings(t, runLocal, "connect-stream soft kpi",
		`CONNECT_STREAM_SOFT_MIN_UP`,
		`CONNECT_STREAM_SOFT_MIN_DOWN`,
		`"4.0"`,
		`def is_connect_stream_profile`,
		`def connect_stream_soft_kpi_warn`,
		`WARN connect-stream soft KPI`,
		`connect-stream soft warn below`,
	)
	if dockerBenchConnectStreamSoftMin != 4.0 {
		t.Fatalf("dockerBenchConnectStreamSoftMin=%v want 4.0", dockerBenchConnectStreamSoftMin)
	}
	requireSubstrings(t, matrixDoc, "connect-stream asymmetry",
		"CONNECT-stream bidi asymmetry",
		"~991 / ~130",
		"Soft gate",
		"`connect-stream-h3`",
		"TestMasqueDockerBenchConnectStreamSoftKPIContract",
	)
}

// TestMasqueDockerBenchConnectStreamVPSKPIContract locks field KPI path for P0 connect-stream.
func TestMasqueDockerBenchConnectStreamVPSKPIContract(t *testing.T) {
	t.Parallel()
	vpsRun := readVPSBenchSource(t, "run.py")
	vpsInvoke := readVPSBenchSource(t, "invoke.py")
	vpsMatrix := readVPSBenchSource(t, "run_matrix.py")
	vpsCommon := readVPSBenchSource(t, "masque_bench_common.py")
	vpsReadme := readVPSBenchSource(t, "README.md")
	coreRun := readRepoSource(t, filepath.Join("docker", "masque-core-bench", "run.py"))
	matrixDoc := readRepoSource(t, filepath.Join("docs", "masque", "benchmark-matrix.md"))

	requireSubstrings(t, vpsRun, "vps kpi verdict",
		"BENCH_KPI_DOWN_MBIT",
		"connect_stream_kpi_enabled",
		"print_connect_stream_kpi_verdict",
	)
	requireSubstrings(t, vpsInvoke, "vps invoke stream",
		"MASQUE_TCP_USE_CONNECT_STREAM",
		"BENCH_KPI_DOWN_MBIT=21",
		"BENCH_IPERF_DOWN_FIRST=1",
		"BENCH_FIELD_WAIT_SEC",
		"BENCH_SUI_DIAL_HOST",
		"bench_sui_dial_host",
		"ref1_hairpin_dial_error",
		"ref1_wait_masque_online",
		"field-bench-local fallback",
		"ref1_field_prod_env",
		"ref1_client_prod_env",
		"ref1_remote_sui_redeploy_needed",
		"write_bench_env",
		"ensure_singbox_artifact",
		"--with-sui-redeploy",
		"--sui-binary-only",
		"redeploy-binary-native",
		"--validate-local",
		"--field-bench-local",
		"ref1_field_vps_wait_sec",
		"field_bench_local_ref1",
		"ref1_field_refresh_remote_kpi",
		"_ref1_field_kpi_redeploy_retry_enabled",
		"REF1_FIELD_KPI_REDEPLOY_RETRY",
		"return_tcp_down=True",
		"docker remote client",
		"--field-vps",
		"_ref1_field_run_colocated_matrix",
		"REF1_FIELD_RUN_COLOCATED",
		"--snapshot-slug",
		"--wait-refresh",
		`cfg.get("BENCH_LEGS")`,
		"validate_local_ref1",
        "redeploy_sui_panel",
        "ref1_verify_remote_sui_masque",
        "K-REF-B",
		`"h3,h3-h2o`,
		"MASQUE_SERVER=127.0.0.1",
		"_SSH_RETRY_ATTEMPTS",
		"ConnectTimeout",
	)
    requireSubstrings(t, vpsCommon, "vps common client prod env",
        "ref1_client_prod_env",
        "_REF1_CLIENT_PROD_DEFAULTS",
        "REF1_FIELD_PROD_DEFAULTS",
        "ref1_field_prod_env",
        "MASQUE_QUIC_DOWNLOAD_EAGER_WINDOW",
        "MASQUE_H3_BIDI_DOWNLOAD_DRAIN",
        "MASQUE_QUIC_HANDSHAKE_IDLE_MS",
        "MASQUE_CONNECT_STREAM_DIAL_MAX_ATTEMPTS",
        "MASQUE_CONNECT_STREAM_DIAL_BACKOFF_MS",
        "QUIC_GO_DISABLE_GSO",
        "QUIC_GO_DISABLE_ECN",
        "ref1_verify_remote_sui_masque",
        "ref1_verify_remote_sui_masque_env",
        "ref1_remote_sui_redeploy_needed",
        "REF1_FIELD_FORCE_REDEPLOY",
        "sing_box_process_env",
    )
	requireSubstrings(t, vpsCommon, "vps common kpi",
		"connect_stream_kpi_enabled",
		"bench_iperf_down_first",
		"BENCH_IPERF_DOWN_FIRST",
		"print_connect_stream_kpi_verdict",
		"VERDICT",
		"MASQUE_TCP_USE_CONNECT_STREAM",
		"enable_monitoring",
		"transport_mode == \"connect_ip\"",
		"MASQUE_BENCH_SKIP_URL_TEST",
		"_LOCAL_DOCKER_CONNECT_STREAM_PROFILE",
		"connect-stream-h3-tun",
	)
	monitoringSrc := readRepoSource(t, filepath.Join("hiddify-core", "hiddify-sing-box", "common", "monitoring", "bench_skip_env.go"))
	requireSubstrings(t, monitoringSrc, "bench skip url test impl",
		"MASQUE_BENCH_SKIP_URL_TEST",
		"BenchSkipURLTest",
	)
	requireSubstrings(t, vpsMatrix, "vps matrix kpi",
		"connect_stream_kpi_enabled",
		"print_connect_stream_kpi_verdict",
		"BENCH_IPERF_DOWN_FIRST",
		"bench_sui_dial_host",
		`sui_dial`,
		`p in ("h3", "h3-sb-stream")`,
	)
	requireSubstrings(t, vpsCommon, "vps common sui dial",
		"bench_sui_dial_host",
		"bench_masque_endpoint_server",
		"BENCH_SUI_DIAL_HOST",
		"hairpin",
	)
	requireSubstrings(t, vpsMatrix, "vps matrix sidecar loopback",
		`"MASQUE_SERVER": "127.0.0.1"`,
	)
	requireSubstrings(t, vpsReadme, "vps readme stream",
		"MASQUE_TCP_USE_CONNECT_STREAM=1",
		"P0 CONNECT-stream",
	)
	requireSubstrings(t, coreRun, "core bench kpi",
		"BENCH_KPI_DOWN_MBIT",
		"21.0",
	)
	requireSubstrings(t, matrixDoc, "vps kpi doc",
		"TestMasqueDockerBenchConnectStreamVPSKPIContract",
		"tcp_down > 21",
	)
	if dockerBenchConnectStreamVPSKPITarget != 21.0 {
		t.Fatalf("dockerBenchConnectStreamVPSKPITarget=%v want 21.0", dockerBenchConnectStreamVPSKPITarget)
	}
	dialGo := readRepoSource(t, filepath.Join("hiddify-core", "hiddify-sing-box", "transport", "masque", "session", "dial.go"))
	requireSubstrings(t, dialGo, "quic dial hairpin",
		"isLoopbackDialHost",
		"REF1-2 hairpin",
		"ResolveTLSServerName",
	)
}

// TestMasqueSUIProdEnvContract locks s-ui container env for K-REF-B server :4438 prod tuning.
func TestMasqueSUIProdEnvContract(t *testing.T) {
	t.Parallel()
	compose := readRepoSource(t, filepath.Join("vendor", "s-ui", "docker-compose.stand.yml"))
	runPy := readRepoSource(t, filepath.Join("vendor", "s-ui", "run.py"))
	for _, key := range []string{
		"MASQUE_QUIC_DOWNLOAD_EAGER_WINDOW",
		"MASQUE_QUIC_KEEPALIVE_MS",
		"MASQUE_QUIC_HANDSHAKE_IDLE_MS",
		"MASQUE_H3_BIDI_UPLOAD_WAKE",
		"MASQUE_H3_BIDI_DOWNLOAD_WAKE",
		"MASQUE_H3_BIDI_DOWNLOAD_DRAIN",
		"MASQUE_RELAY_BIDI_DOWNLOAD_WRITE_WAKE",
		"MASQUE_RELAY_TCP_STREAM_HIJACK",
		"MASQUE_CONNECT_STREAM_PIPE_UPLOAD",
		"QUIC_GO_DISABLE_GSO",
		"QUIC_GO_DISABLE_ECN",
	} {
		requireSubstrings(t, compose, "s-ui compose prod env", key+":")
		requireSubstrings(t, runPy, "s-ui run compose env", `"`+key+`"`)
	}
}

// TestMasqueSUIRedeployBinaryNativeTagsContract locks --sui-binary-only server build includes with_masque.
func TestMasqueSUIRedeployBinaryNativeTagsContract(t *testing.T) {
	t.Parallel()
	runPy := readRepoSource(t, filepath.Join("vendor", "s-ui", "run.py"))
	invokePy := readVPSBenchSource(t, "invoke.py")
	requireSubstrings(t, runPy, "s-ui native build tags",
		"print_core_build_tags",
		"_sui_native_linux_build_tags",
		"with_masque",
		"with_purego",
		"redeploy-binary-native",
		"cmd_push_compose",
		"cmd_up",
		"-checklinkname=0",
		`"-tags"`,
	)
	requireSubstrings(t, invokePy, "invoke ssh resilience",
		"_ssh_base_opts",
		"ConnectTimeout",
		"_SSH_RETRY_ATTEMPTS",
		"_run_remote_matrix",
	)
}

// TestMasqueDockerBenchConnectStreamH3KPIContract locks local docker K-REF-B gate for connect-stream-h3.
func TestMasqueDockerBenchConnectStreamH3KPIContract(t *testing.T) {
	t.Parallel()
	runLocal := readDockerBenchSource(t, "run_local.py")
	localProfiles := readDockerBenchSource(t, "local_profiles.py")
	compose := readRepoSource(t, filepath.Join("docker", "masque-perf-lab", "docker-compose.yml"))
	ceilingSrc := readRepoSource(t, filepath.Join("hiddify-core", "hiddify-sing-box", "transport", "masque", "connect_stream_ceiling_test.go"))
	endpointSrc := readRepoSource(t, filepath.Join("hiddify-core", "hiddify-sing-box", "protocol", "masque", "endpoint_connect_stream_download_test.go"))
	history := readRepoSource(t, filepath.Join("docs", "masque", "bench-history", "2026-06-13-ref1-2-local-docker.md"))
	matrixDoc := readRepoSource(t, filepath.Join("docs", "masque", "benchmark-matrix.md"))

	requireSubstrings(t, runLocal, "connect-stream-h3 hard kpi",
		`BENCH_CONNECT_STREAM_MIN_DOWN_MBIT", "21"`,
		`CONNECT_STREAM_MIN_DOWN = float`,
		`def connect_stream_kpi_ok`,
		`connect_stream_kpi_hard_profiles`,
		`connect-stream-h3-tun`,
		`connect-stream-h3/h3-tun KPI min tcp_down=`,
		`connect-stream: download-first`,
		`connect-stream tun: download-first`,
		`wait_connect_stream_tcp_ready`,
		`restart", "iperf-server"`,
	)
	requireSubstrings(t, compose, "perf-lab server prod env",
		"MASQUE_QUIC_DOWNLOAD_EAGER_WINDOW",
		"MASQUE_QUIC_HANDSHAKE_IDLE_MS",
		"MASQUE_RELAY_TCP_STREAM_HIJACK",
	)
	requireSubstrings(t, compose, "perf-lab client prod env",
		"masque-client-core",
		"MASQUE_H3_BIDI_DOWNLOAD_DRAIN",
		"MASQUE_H3_BIDI_DOWNLOAD_WAKE",
	)
	runField := readDockerBenchSource(t, "run_field_h3_remote.py")
	requireSubstrings(t, runField, "field remote bench",
		"ref1_client_prod_env",
		"masque-remote-client",
		"print_connect_stream_kpi_verdict",
		"field-h3",
		"--snapshot-slug",
		"ref1_write_bench_snapshot",
	)
	requireSubstrings(t, localProfiles, "connect-stream-h3 monitoring skip",
		`profile.tcp_transport == "connect_stream"`,
		`skip_monitoring`,
		`MASQUE_QUIC_DOWNLOAD_EAGER_WINDOW`,
		`MASQUE_H3_BIDI_DOWNLOAD_DRAIN`,
		`MASQUE_BENCH_SKIP_URL_TEST`,
	)
	requireSubstrings(t, localProfiles, "connect-stream-h3-tun field parity",
		`name="connect-stream-h3-tun"`,
		`via="tun"`,
		`tcp_transport="connect_stream"`,
		`gvisor`,
		`172.30.99.0/24`,
		`field/VPS parity`,
	)
	requireSubstrings(t, ceilingSrc, "in-proc docker h3 guard",
		"TestConnectStreamDockerH3KPIInProcGuard",
		"connectStreamVPSKPITargetDownMbps",
	)
	requireSubstrings(t, endpointSrc, "endpoint prod windowed kpi",
		"windowed_prod_client",
		"windowed_prod_hijack",
		"endpointH3RelayResponse",
		"endpointProdWindowedLink",
		"K-REF-B s-ui path",
	)
	requireSubstrings(t, history, "ref1-2 local docker",
		"connect-stream-h3",
		"**68.0**",
		"KPI >21",
		"K-REF-B",
	)
	requireSubstrings(t, matrixDoc, "connect-stream h3 kpi",
		"connect-stream-h3",
		"TestMasqueDockerBenchConnectStreamH3KPIContract",
	)
	if dockerBenchConnectStreamMinDownMbit != 21.0 {
		t.Fatalf("dockerBenchConnectStreamMinDownMbit=%v want 21.0", dockerBenchConnectStreamMinDownMbit)
	}
}

// TestMasqueFieldBenchReportDownFirstContract locks field remote iperf order (run_field_h3_remote.py).
func TestMasqueFieldBenchReportDownFirstContract(t *testing.T) {
	t.Parallel()
	reportSh := readRepoSource(t, filepath.Join("docker", "masque-perf-lab", "bench", "run-bench-report.sh"))
	runField := readDockerBenchSource(t, "run_field_h3_remote.py")
	requireSubstrings(t, reportSh, "field bench down-first order",
		`BENCH_IPERF_DOWN_FIRST:-0}" = "1"`,
		`run_one "-R"`,
		`run_one ""`,
		"download (-R) before upload",
	)
	// Down-first branch must run -R before plain upload (not upload-then-download on success).
	dfIdx := strings.Index(reportSh, `BENCH_IPERF_DOWN_FIRST:-0}" = "1"`)
	if dfIdx < 0 {
		t.Fatal("missing down-first branch")
	}
	branch := reportSh[dfIdx:]
	downIdx := strings.Index(branch, `run_one "-R"`)
	upIdx := strings.Index(branch, `run_one ""`)
	if downIdx < 0 || upIdx < 0 || downIdx > upIdx {
		t.Fatalf("down-first branch order: down@=%d up@=%d", downIdx, upIdx)
	}
	requireSubstrings(t, runField, "field remote down-first env",
		"BENCH_IPERF_DOWN_FIRST=1",
		"run-bench-report.sh",
	)
}

func readVPSBenchSource(t *testing.T, name string) string {
	t.Helper()
	root := findDockerVPSBenchRoot(t)
	path := filepath.Join(root, name)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(data)
}

func findDockerVPSBenchRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	dir := wd
	for range 10 {
		root := filepath.Join(dir, "docker", "masque-vps-bench")
		if _, err := os.Stat(filepath.Join(root, "run.py")); err == nil {
			return root
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Fatalf("docker/masque-vps-bench not found (run from hiddify-app checkout)")
	return ""
}

// TestMasqueDockerBenchCISmokeContract locks optional CI jobs: connect-ip-h3-tun + connect-udp paced, soft-fail artifact.
func TestMasqueDockerBenchCISmokeContract(t *testing.T) {
	t.Parallel()
	workflow := readRepoSource(t, filepath.Join(".github", "workflows", "masque-docker-smoke.yml"))
	buildSh := readRepoSource(t, filepath.Join("scripts", "build-masque-perf-lab.sh"))
	matrixDoc := readRepoSource(t, filepath.Join("docs", "masque", "benchmark-matrix.md"))

	requireSubstrings(t, workflow, "ci smoke workflow",
		"continue-on-error",
		"connect-ip-h3-tun",
		"connect-stream-h3",
		"connect-udp-h3",
		"connect-udp-h2",
		"LOCAL_STRICT",
		"upload-artifact",
		"masque-docker-smoke-bench",
		"build-masque-perf-lab.sh",
	)
	requireSubstrings(t, buildSh, "build script",
		"with_masque",
		"sing-box-linux-amd64",
		"docker compose build",
	)
	requireSubstrings(t, matrixDoc, "ci smoke doc",
		"masque-docker-smoke.yml",
		"TestMasqueDockerBenchCISmokeContract",
		"connect-stream-h3",
		"connect-udp-h3",
	)
}

// TestMasqueDockerBenchConnectUDPPipeUploadContract documents connect-udp-h3 TCP asymmetry:
// same transport_mode=connect_udp as connect-stream-h3; difference is MASQUE_CONNECT_STREAM_PIPE_UPLOAD.
func TestMasqueDockerBenchConnectUDPPipeUploadContract(t *testing.T) {
	t.Parallel()
	local := readDockerBenchSource(t, "local_profiles.py")
	matrixDoc := readRepoSource(t, filepath.Join("docs", "masque", "benchmark-matrix.md"))
	gapsDoc := readRepoSource(t, filepath.Join("docs", "masque", "layers", "GAPS.md"))

	requireSubstrings(t, local, "connect-udp-h3 pipe",
		`name="connect-udp-h3"`,
		`transport_mode="connect_udp"`,
		`pipe_upload=True`,
		`MASQUE_CONNECT_STREAM_PIPE_UPLOAD`,
	)
	requireSubstrings(t, local, "connect-stream-h3 bidi",
		`name="connect-stream-h3"`,
		`pipe_upload=False`,
	)
	requireSubstrings(t, matrixDoc, "connect-udp pipe_upload",
		"`connect-udp-h3`",
		"`connect-stream-h3`",
		"pipe_upload",
		"MASQUE_CONNECT_STREAM_PIPE_UPLOAD",
		"~125–873",
		"~60–119",
		"TestMasqueDockerBenchConnectUDPPipeUploadContract",
	)
	requireSubstrings(t, gapsDoc, "G43 pipe_upload",
		"G43",
		"pipe_upload",
		"connect-udp-h3 vs connect-stream-h3",
	)
}

// TestMasqueDockerBenchUDPBurstCeilingContract locks max-burst informational metrics (BENCH_UDP_MODE=both).
func TestMasqueDockerBenchUDPBurstCeilingContract(t *testing.T) {
	t.Parallel()
	runLocal := readDockerBenchSource(t, "run_local.py")
	history := readRepoSource(t, filepath.Join("docs", "masque", "bench-history", "2026-06-13-connect-udp-post-h2-flush.md"))
	matrixDoc := readRepoSource(t, filepath.Join("docs", "masque", "benchmark-matrix.md"))

	requireSubstrings(t, runLocal, "udp burst info",
		`informational (loss at unlimited rate is expected`,
		`connect-udp max burst`,
		`UDP_MAX_TARGET_MBIT`,
	)
	requireSubstrings(t, history, "max burst h3",
		"connect-udp-h3",
		"86.0",
		"123.25",
		"14.0",
	)
	requireSubstrings(t, history, "max burst h2",
		"connect-udp-h2",
		"87.36",
		"116.31",
		"12.6",
	)
	requireSubstrings(t, matrixDoc, "max burst doc",
		"Max burst",
		"informational",
		"connect-udp-h2",
		"TestMasqueDockerBenchUDPBurstCeilingContract",
	)
	if connectudp.ObservedMaxBurstLossPct < 80 || connectudp.ObservedMaxBurstLossPct > 90 {
		t.Fatalf("ObservedMaxBurstLossPct=%v want ~86", connectudp.ObservedMaxBurstLossPct)
	}
	if connectudp.ObservedMaxBurstMbit < 100 {
		t.Fatalf("ObservedMaxBurstMbit=%v want >=100", connectudp.ObservedMaxBurstMbit)
	}
	if connectudp.ObservedMaxBurstH2LossPct < 80 || connectudp.ObservedMaxBurstH2LossPct > 90 {
		t.Fatalf("ObservedMaxBurstH2LossPct=%v want ~87", connectudp.ObservedMaxBurstH2LossPct)
	}
	if connectudp.ObservedMaxBurstH2Mbit < 100 {
		t.Fatalf("ObservedMaxBurstH2Mbit=%v want >=100", connectudp.ObservedMaxBurstH2Mbit)
	}
}

// TestMasqueDockerBenchUDPCalibrationSweepContract locks target/RTT sweep script and bench-history evidence.
func TestMasqueDockerBenchUDPCalibrationSweepContract(t *testing.T) {
	t.Parallel()
	sweep := readDockerBenchSource(t, "run_udp_calibration_sweep.py")
	history := readRepoSource(t, filepath.Join("docs", "masque", "bench-history", "2026-06-13-connect-udp-calibration-sweep.md"))
	matrixDoc := readRepoSource(t, filepath.Join("docs", "masque", "benchmark-matrix.md"))

	requireSubstrings(t, sweep, "sweep targets",
		`SWEEP_TARGETS = [4.0, 8.0, 12.0, 16.0]`,
		`SWEEP_NETEM_MS = [35, 50, 70]`,
		`connect-udp-h3`,
		`udp-calibration-sweep.md`,
	)
	requireSubstrings(t, history, "target sweep",
		"Target sweep @ netem 35 ms",
		"| 4 |",
		"| 8 |",
		"| 12 |",
		"| 16 |",
	)
	requireSubstrings(t, history, "rtt sweep",
		"RTT sweep @ target 8 Mbit/s",
		"| 35 |",
		"| 50 |",
		"| 70 |",
	)
	requireSubstrings(t, matrixDoc, "calibration sweep",
		"run_udp_calibration_sweep.py",
		"TestMasqueDockerBenchUDPCalibrationSweepContract",
	)
}

// TestMasqueDockerBenchUDPHashIntegrityContract locks paced fill_sha256 vs zero-corpus precompute.
func TestMasqueDockerBenchUDPHashIntegrityContract(t *testing.T) {
	t.Parallel()
	runLocal := readDockerBenchSource(t, "run_local.py")
	analyze := readDockerBenchSource(t, filepath.Join("bench", "udp_sink_analyze.py"))

	requireSubstrings(t, runLocal, "udp hash integrity",
		`def udp_fill_hash_integrity_ok`,
		`fill_sha256`,
		`zero_corpus_hash`,
		`fill hash mismatch`,
	)
	requireSubstrings(t, analyze, "zero corpus",
		`def zero_corpus_hash`,
		`RESULT_UDP_FILL_SHA256`,
	)

	const rxPkts = 4877 // typical paced run @ 3s (bench-history 2026-05-19)
	got := connectudp.UDPProbeFillSHA256(rxPkts, connectudp.DefaultBenchUDPPayloadLen)
	if len(got) != 64 {
		t.Fatalf("UDPProbeFillSHA256 len=%d want 64", len(got))
	}
	if connectudp.UDPProbeHeaderLen != 12 {
		t.Fatalf("UDPProbeHeaderLen=%d want 12", connectudp.UDPProbeHeaderLen)
	}
}

// TestMasqueDockerBenchConnectUDPSoftKPIContract locks informational TCP soft gate for connect-udp profiles.
func TestMasqueDockerBenchConnectUDPSoftKPIContract(t *testing.T) {
	t.Parallel()
	runLocal := readDockerBenchSource(t, "run_local.py")
	matrixDoc := readRepoSource(t, filepath.Join("docs", "masque", "benchmark-matrix.md"))

	requireSubstrings(t, runLocal, "connect-udp soft kpi",
		`CONNECT_UDP_SOFT_MIN_TCP_DOWN`,
		`CONNECT_UDP_SOFT_MAX_UP_DOWN_RATIO`,
		`"50.0"`,
		`"8.0"`,
		`def is_connect_udp_profile`,
		`def connect_udp_soft_kpi_warn`,
		`WARN connect-udp soft KPI`,
		`connect-udp soft warn tcp_down<`,
	)
	if dockerBenchConnectUDPSoftMinDown != 50.0 {
		t.Fatalf("dockerBenchConnectUDPSoftMinDown=%v want 50.0", dockerBenchConnectUDPSoftMinDown)
	}
	if dockerBenchConnectUDPSoftMaxRatio != 8.0 {
		t.Fatalf("dockerBenchConnectUDPSoftMaxRatio=%v want 8.0", dockerBenchConnectUDPSoftMaxRatio)
	}
	requireSubstrings(t, matrixDoc, "connect-udp tcp soft",
		"connect-udp-h3",
		"~60–119",
		"Soft gate",
		"TestMasqueDockerBenchConnectUDPSoftKPIContract",
	)
}

// TestMasqueDockerBenchConnectIPH3TunKPIContract locks connect-ip-h3-tun docker thresholds and in-proc guard.
func TestMasqueDockerBenchConnectIPH3TunKPIContract(t *testing.T) {
	t.Parallel()
	runLocal := readDockerBenchSource(t, "run_local.py")
	history := readRepoSource(t, filepath.Join("docs", "masque", "bench-history", "2026-06-13-ingress-burst-wake-coalesce.md"))
	localizeSrc := readRepoSource(t, filepath.Join("hiddify-core", "hiddify-sing-box", "transport", "masque", "connect_ip_localize_test.go"))

	requireSubstrings(t, runLocal, "connect-ip KPI thresholds",
		`BENCH_CONNECT_IP_MIN_UP_MBIT", "80"`,
		`BENCH_CONNECT_IP_MIN_DOWN_MBIT", "350"`,
		`CONNECT_IP_MIN_DOWN = float(os.environ.get("BENCH_CONNECT_IP_MIN_DOWN_MBIT", "350"))`,
	)
	requireSubstrings(t, history, "connect-ip-h3-tun baseline",
		"connect-ip-h3-tun",
		"**104**",
		"**786**",
		"down ≥ 350",
	)
	requireSubstrings(t, localizeSrc, "in-proc docker KPI guard",
		"TestConnectIPDockerTUNKPIInProcGuard",
		"connectIPLocalizeFastMbps",
	)
	if dockerBenchConnectIPMinUpMbit != 80.0 || dockerBenchConnectIPMinDownMbit != 350.0 {
		t.Fatalf("connect-ip docker KPI constants up=%v down=%v want 80/350",
			dockerBenchConnectIPMinUpMbit, dockerBenchConnectIPMinDownMbit)
	}
}

// TestMasqueDockerBenchConnectIPH2BaselineContract locks connect-ip-h2 profile mapping and bench-history evidence.
func TestMasqueDockerBenchConnectIPH2BaselineContract(t *testing.T) {
	t.Parallel()
	local := readDockerBenchSource(t, "local_profiles.py")
	history := readRepoSource(t, filepath.Join("docs", "masque", "bench-history", "2026-06-13-connect-ip-h2-baseline.md"))
	matrixDoc := readRepoSource(t, filepath.Join("docs", "masque", "benchmark-matrix.md"))
	gapsDoc := readRepoSource(t, filepath.Join("docs", "masque", "layers", "GAPS.md"))
	serverSrc := readRepoSource(t, filepath.Join("hiddify-core", "hiddify-sing-box", "protocol", "masque", "server", "endpoint_serve_launch_h2_e2e_test.go"))

	requireSubstrings(t, local, "connect-ip-h2 profile",
		`name="connect-ip-h2"`,
		`transport_mode="connect_ip"`,
		`http_layer="h2"`,
		`tcp_transport="connect_stream"`,
		`via="socks"`,
	)
	requireSubstrings(t, history, "connect-ip-h2 baseline",
		"connect-ip-h2",
		"LaunchMasqueStack",
		"TestLaunchMasqueStackH2ExtendedConnectIPSmoke",
		"connect-ip-h3",
	)
	requireSubstrings(t, matrixDoc, "connect-ip-h2 map",
		"`connect-ip-h2`",
		"connect_stream",
		"hybrid, h2",
	)
	requireSubstrings(t, gapsDoc, "G64 closed",
		"G64",
		"connect-ip-h2",
		"**closed**",
	)
	requireSubstrings(t, serverSrc, "launch h2 e2e",
		"TestLaunchMasqueStackH2ExtendedConnectIPSmoke",
		"LaunchMasqueStack",
		"HandleConnectIPRequest",
	)
}

// TestMasqueDockerBenchConnectStreamH2BaselineContract locks connect-stream-h2 profile mapping,
// monitoring skip (H2 bidi upload hang), and bench-history / in-proc upload drain evidence.
func TestMasqueDockerBenchConnectStreamH2BaselineContract(t *testing.T) {
	t.Parallel()
	local := readDockerBenchSource(t, "local_profiles.py")
	history := readRepoSource(t, filepath.Join("docs", "masque", "bench-history", "2026-06-13-connect-stream-h2-baseline.md"))
	matrixDoc := readRepoSource(t, filepath.Join("docs", "masque", "benchmark-matrix.md"))
	streamTest := readRepoSource(t, filepath.Join("hiddify-core", "hiddify-sing-box", "transport", "masque", "stream", "tunnel_conn_test.go"))
	benchTest := readRepoSource(t, filepath.Join("hiddify-core", "hiddify-sing-box", "transport", "masque", "h2_connect_stream_bench_test.go"))

	requireSubstrings(t, local, "connect-stream-h2 profile",
		`name="connect-stream-h2"`,
		`transport_mode="connect_udp"`,
		`http_layer="h2"`,
		`tcp_transport="connect_stream"`,
		`warmup_sec=15`,
	)
	requireSubstrings(t, local, "connect-stream-h2 monitoring skip",
		`profile.tcp_transport == "connect_stream"`,
		`skip_monitoring`,
	)
	requireSubstrings(t, history, "connect-stream-h2 baseline",
		"connect-stream-h2",
		"MASQUE_H2_BIDI_DOWNLOAD_DRAIN",
		"TestTunnelConnReadFromUploadDrainsPendingDownload",
	)
	requireSubstrings(t, matrixDoc, "connect-stream-h2 map",
		"`connect-stream-h2`",
		"TestMasqueDockerBenchConnectStreamH2BaselineContract",
	)
	requireSubstrings(t, streamTest, "tunnel conn drain",
		"TestTunnelConnReadFromUploadDrainsPendingDownload",
		"TestH2BidiTunnelConnWriteUploadDrainsPendingDownload",
		"connect-stream-h2",
	)
	requireSubstrings(t, benchTest, "h2 banner upload",
		"TestH2ConnectStreamTCPUploadServerBannerNoConcurrentRead",
		"TestH2ConnectStreamTCPUploadWriteBannerNoConcurrentRead",
		"MASQUE_H2_BIDI_DOWNLOAD_DRAIN",
	)
}
