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
	dockerBenchUDPMinUpMbit        = 6.0  // paced floor (bench-history 2026-05-19: ~6.66–6.75)
	dockerBenchUDPReproUpTolerance = 0.1  // paced udp_up spread across 3× runs
	dockerBenchConnectStreamSoftMin       = 4.0  // localize floor; soft WARN only (bidi asymmetry expected)
	dockerBenchConnectStreamMinDownMbit   = 21.0 // run_local.py BENCH_CONNECT_STREAM_MIN_DOWN_MBIT (connect-stream-h3)
	dockerBenchConnectStreamGateH3Down    = 100.0 // GATE-H3-D tcp_down floor @ netem 35 ms
	dockerBenchConnectStreamGateH3MaxRatio = 4.0  // GATE-H3-D tcp_up / max(tcp_down, 21) ceiling
	dockerBenchConnectStreamAsymmetryWarnRatio = 8.0 // Phase-1 WARN tcp_up/tcp_down (923/48 baseline ~19)
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
		`wait_connect_ip_native_l3_plane_ready`,
		`wait_connect_ip_tun_native_ready`,
		`warm_connect_ip_tun_before_iperf`,
		`time.sleep(2)`,
		`iperf_direct_in_client(True`,
		`[bench] upload OK`,
		`[bench] download OK`,
	)
	if strings.Contains(src, "HIDDIFY_CONNECT_IP_TUN_POST_RECYCLE") {
		t.Fatal("recycle: HIDDIFY_CONNECT_IP_TUN_POST_RECYCLE crutch must be CUT")
	}
	// nc warm-up must not restart iperf-server before bulk iperf (breaks TCP session priming).
	if strings.Contains(src, `warm-up before download",
                    restart_iperf=True`) {
		t.Fatal("recycle: download warm-up must not restart iperf-server after nc")
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
		`KPI gate (udp_deliv) applies to **paced** phase`,
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
		`3x repro spread`,
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
// connect-ip-h3-tun is local-only (native TUN KPI).
func TestMasqueDockerBenchBenchmarkMatrixContract(t *testing.T) {
	t.Parallel()
	remote := readRepoSource(t, filepath.Join("scripts", "Benchmark-Masque.ps1"))
	local := readDockerBenchSource(t, "local_profiles.py")
	matrixDoc := readRepoSource(t, filepath.Join("docs", "masque", "benchmark-matrix.md"))

	remoteIDs := []string{"h3", "h2"}
	for _, id := range remoteIDs {
		if !strings.Contains(remote, `id = "`+id+`"`) {
			t.Fatalf("Benchmark-Masque.ps1: missing remote profile %q", id)
		}
	}
	if hybridConnectIPProfileRe.MatchString(remote) {
		t.Fatal("Benchmark-Masque.ps1 must not include removed hybrid connect-ip-h3/h2 profiles")
	}
	if strings.Contains(remote, `id = "connect-ip-h3-tun"`) {
		t.Fatal("Benchmark-Masque.ps1 must not include connect-ip-h3-tun profile (local TUN KPI only)")
	}

	localNames := regexp.MustCompile(`name="([^"]+)"`).FindAllStringSubmatch(local, -1)
	byName := map[string]bool{}
	for _, m := range localNames {
		byName[m[1]] = true
	}
	pairs := []struct{ remote, local string }{
		{"h3", "connect-udp-h3"},
		{"h2", "connect-udp-h2"},
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
	if byName["connect-ip-h3"] || byName["connect-ip-h2"] {
		t.Fatal("local_profiles.py: hybrid connect-ip-h3/h2 profiles must be removed")
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
		"--field-refresh",
		"_ref1_field_run_colocated_matrix",
		"REF1_FIELD_RUN_COLOCATED",
		"--snapshot-slug",
		"--wait-refresh",
		`cfg.get("BENCH_LEGS")`,
		"validate_local_ref1",
        "redeploy_sui_panel",
        "ref1_verify_remote_sui_masque",
        "connect-stream-h3",
		`"h3,h2"`,
		"MASQUE_SERVER=127.0.0.1",
		"_SSH_RETRY_ATTEMPTS",
		"ConnectTimeout",
	)
    requireSubstrings(t, vpsCommon, "vps common client prod env",
        "ref1_client_prod_env",
        "ref1_client_prod_defaults",
        "REF1_FIELD_PROD_DEFAULTS",
        "ref1_field_prod_env",
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
		`p == "h3"`,
	)
	if strings.Contains(vpsMatrix, "connect-ip-h3") {
		t.Fatal("run_matrix.py: hybrid connect-ip-h3 leg must be removed (connect_ip+connect_stream is config error)")
	}
	if strings.Contains(vpsMatrix, `MASQUE_TRANSPORT_MODE": "connect_ip"`) &&
		strings.Contains(vpsMatrix, `MASQUE_TCP_TRANSPORT": "connect_stream"`) {
		t.Fatal("run_matrix.py: must not combine connect_ip transport with connect_stream TCP")
	}
	requireSubstrings(t, vpsCommon, "vps common sui dial",
		"bench_sui_dial_host",
		"bench_masque_endpoint_server",
		"BENCH_SUI_DIAL_HOST",
		"hairpin",
	)
	requireSubstrings(t, vpsMatrix, "vps matrix sidecar loopback",
		`"MASQUE_SERVER": sui_dial`,
		`bench_sui_dial_host`,
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

// TestMasqueSUIProdEnvContract locks s-ui container env: slim prod (QUIC-GO only); bidi perf opt-in in run.py.
func TestMasqueSUIProdEnvContract(t *testing.T) {
	t.Parallel()
	compose := readRepoSource(t, filepath.Join("vendor", "s-ui", "docker-compose.stand.yml"))
	runPy := readRepoSource(t, filepath.Join("vendor", "s-ui", "run.py"))
	for _, key := range []string{
		"QUIC_GO_DISABLE_GSO",
		"QUIC_GO_DISABLE_ECN",
	} {
		requireSubstrings(t, compose, "s-ui compose prod env", key+":")
	}
	requireSubstrings(t, compose, "s-ui compose slim comment",
		"Prod slim",
		"SUI_MASQUE_BIDI_PERF_ENV",
	)
	requireSubstrings(t, runPy, "s-ui run bidi opt-in",
		"_REF1_MASQUE_BIDI_PERF_DEFAULTS",
		"SUI_MASQUE_BIDI_PERF_ENV",
		"_ref1_field_prod_defaults",
	)
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

// TestMasqueDockerBenchConnectStreamH3KPIContract locks local docker connect-stream-h3 gate (S113).
func TestMasqueDockerBenchConnectStreamH3KPIContract(t *testing.T) {
	t.Parallel()
	runLocal := readDockerBenchSource(t, "run_local.py")
	localProfiles := readDockerBenchSource(t, "local_profiles.py")
	compose := readRepoSource(t, filepath.Join("docker", "masque-perf-lab", "docker-compose.yml"))
	ceilingSrc := readRepoSource(t, filepath.Join("hiddify-core", "hiddify-sing-box", "transport", "masque", "connect_stream_localize_test.go"))
	endpointSrc := readRepoSource(t, filepath.Join("hiddify-core", "hiddify-sing-box", "protocol", "masque", "endpoint_connect_stream_download_test.go"))
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
		"MASQUE_BENCH_SKIP_URL_TEST",
	)
	requireSubstrings(t, compose, "perf-lab client prod env",
		"masque-client-core",
		"MASQUE_BENCH_SKIP_URL_TEST",
	)
	h3DrainGo := readRepoSource(t, filepath.Join("hiddify-core", "hiddify-sing-box", "transport", "masque", "h3", "bidi_wake.go"))
	requireSubstrings(t, localProfiles, "connect-stream-h3 zero-env client",
		`def client_env`,
		`MASQUE_BENCH_SKIP_URL_TEST`,
		`skip_monitoring`,
	)
	requireSubstrings(t, h3DrainGo, "h3 bidi wake prod",
		"wakeBidiSendAfterUpload",
		"BidiWakeSink",
	)
	requireSubstrings(t, localProfiles, "connect-stream-h3-tun field parity",
		`name="connect-stream-h3-tun"`,
		`via="tun"`,
		`tcp_transport="connect_stream"`,
		`gvisor`,
		`172.30.99.0/24`,
	)
	requireSubstrings(t, ceilingSrc, "in-proc docker h3 guard",
		"connectStreamVPSKPITargetDownMbps",
		"benchWindowedBidiLink()",
	)
	requireSubstrings(t, endpointSrc, "endpoint prod windowed kpi",
		"windowed_prod_client",
		"windowed_prod_hijack",
		"endpointH3RelayResponse",
		"endpointProdWindowedLink",
		"connect-stream-h3 KPI",
	)
	requireSubstrings(t, matrixDoc, "connect-stream h3 kpi",
		"connect-stream-h3",
		"TestMasqueDockerBenchConnectStreamH3KPIContract",
	)
	if dockerBenchConnectStreamMinDownMbit != 21.0 {
		t.Fatalf("dockerBenchConnectStreamMinDownMbit=%v want 21.0", dockerBenchConnectStreamMinDownMbit)
	}
}

// TestH3ConnectStreamFidelityContract (H3-T6-01) documents synth/Docker fidelity gap: K-S1/K-S2
// are not Docker predictors; Docker bench uses sequential download-first legs on one QUIC session.
func TestH3ConnectStreamFidelityContract(t *testing.T) {
	t.Parallel()
	localizeSrc := readRepoSource(t, filepath.Join("hiddify-core", "hiddify-sing-box", "transport", "masque", "connect_stream_localize_test.go"))
	asymSrc := readRepoSource(t, filepath.Join("hiddify-core", "hiddify-sing-box", "transport", "masque", "h3_connect_stream_asymmetry_test.go"))
	runLocal := readDockerBenchSource(t, "run_local.py")
	h3Readme := readRepoSource(t, filepath.Join("docs", "masque", "layers", "h3", "README.md"))

	requireSubstrings(t, localizeSrc, "K-S1 synth",
		"connectStreamLocalizeDownloadKPIMin",
		"TestMasqueConnectStreamLocalizeDownloadWriteTo",
		"benchWindowedBidiLink()",
	)
	requireSubstrings(t, asymSrc, "H3 strict asymmetry gate",
		"benchWindowedBidiLinkStrictH3L256",
		"TestH3ConnectStreamBidiAsymmetryRatio",
		"h3AsymmetryMinDownMbps",
	)
	requireSubstrings(t, runLocal, "sequential docker legs",
		"connect-stream: download-first",
		"iperf_via_socks(True)",
		"iperf_via_socks(False)",
	)
	requireSubstrings(t, h3Readme, "H3-S symptoms",
		"H3-S1",
		"H3-S2",
		"H3-S3",
		"sequential",
	)
	if strings.Contains(localizeSrc, "NotDockerPredictor") {
		t.Log("K-S1/K-S2 marked NotDockerPredictor in localize tests")
	}
}

// TestMasqueDockerBenchConnectStreamH3AsymmetryContract (H3-T6-11) locks GATE-H3-D ratio KPI
// in run_local.py: WARN ratio>8, LOCAL_STRICT FAIL, hard down>100 and ratio≤4.
func TestMasqueDockerBenchConnectStreamH3AsymmetryContract(t *testing.T) {
	t.Parallel()
	runLocal := readDockerBenchSource(t, "run_local.py")
	matrixDoc := readRepoSource(t, filepath.Join("docs", "masque", "benchmark-matrix.md"))

	requireSubstrings(t, runLocal, "connect-stream h3 asymmetry warn",
		`CONNECT_STREAM_ASYMMETRY_WARN_RATIO`,
		`"8"`,
		`def connect_stream_h3_asymmetry_warn`,
		`WARN connect-stream-h3 asymmetry`,
	)
	requireSubstrings(t, runLocal, "GATE-H3-D hard",
		`CONNECT_STREAM_GATE_H3_DOWN_MBIT`,
		`"100"`,
		`CONNECT_STREAM_GATE_H3_MAX_RATIO`,
		`"4"`,
		`def connect_stream_gate_h3_d_ok`,
		`GATE-H3-D`,
	)
	requireSubstrings(t, matrixDoc, "GATE-H3-D baseline",
		"GATE-H3-D",
		"923",
		"48",
		"download-first",
	)
	if dockerBenchConnectStreamGateH3Down != 100.0 {
		t.Fatalf("dockerBenchConnectStreamGateH3Down=%v want 100.0", dockerBenchConnectStreamGateH3Down)
	}
	if dockerBenchConnectStreamGateH3MaxRatio != 4.0 {
		t.Fatalf("dockerBenchConnectStreamGateH3MaxRatio=%v want 4.0", dockerBenchConnectStreamGateH3MaxRatio)
	}
	if dockerBenchConnectStreamAsymmetryWarnRatio != 8.0 {
		t.Fatalf("dockerBenchConnectStreamAsymmetryWarnRatio=%v want 8.0", dockerBenchConnectStreamAsymmetryWarnRatio)
	}
}

// TestMasqueFieldBenchReportDownFirstContract locks bench iperf download-first order.
func TestMasqueFieldBenchReportDownFirstContract(t *testing.T) {
	t.Parallel()
	reportSh := readRepoSource(t, filepath.Join("docker", "masque-perf-lab", "bench", "run-bench-report.sh"))
	runLocal := readDockerBenchSource(t, "run_local.py")
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
	requireSubstrings(t, runLocal, "local bench down-first",
		"download-first",
		"connect_stream_kpi_hard_profiles",
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
	gapsDoc := readRepoSource(t, filepath.Join("docs", "masque", "benchmark-matrix.md"))

	requireSubstrings(t, local, "connect-udp-h3 pipe",
		`name="connect-udp-h3"`,
		`transport_mode="connect_udp"`,
		`pipe_upload=False`,
	)
	requireSubstrings(t, local, "connect-stream-h3 bidi",
		`name="connect-stream-h3"`,
		`pipe_upload=False`,
	)
	tunnelGo := readRepoSource(t, filepath.Join("hiddify-core", "hiddify-sing-box", "transport", "masque", "h3", "tunnel.go"))
	requireSubstrings(t, tunnelGo, "connect-stream prod nil body",
		"nil Body",
		"tunneled upload on the bidi stream",
	)
	requireSubstrings(t, matrixDoc, "connect-udp pipe_upload",
		"`connect-udp-h3`",
		"`connect-stream-h3`",
		"pipe_upload",
		"~125–873",
		"~60–119",
		"TestMasqueDockerBenchConnectUDPPipeUploadContract",
	)
	requireSubstrings(t, gapsDoc, "pipe_upload matrix",
		"pipe_upload",
		"connect-udp-h3 vs connect-stream-h3",
		"TestMasqueDockerBenchConnectUDPPipeUploadContract",
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
		`(below baseline band`,
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

// TestMasqueDockerBenchConnectUDPH3H2CapsuleContract locks connect-udp-h3/h2 prod profiles and in-proc capsule smoke gate.
func TestMasqueDockerBenchConnectUDPH3H2CapsuleContract(t *testing.T) {
	t.Parallel()
	local := readDockerBenchSource(t, "local_profiles.py")
	smokeSrc := readRepoSource(t, filepath.Join("hiddify-core", "hiddify-sing-box", "transport", "masque", "connect_udp_prod_profile_smoke_test.go"))
	gates := readRepoSource(t, filepath.Join("hiddify-core", "scripts", "go-test-masque-gates.ps1"))

	requireSubstrings(t, local, "connect-udp-h3 profile",
		`name="connect-udp-h3"`,
		`transport_mode="connect_udp"`,
		`http_layer="h3"`,
		`tcp_transport="connect_stream"`,
	)
	requireSubstrings(t, local, "connect-udp-h2 profile",
		`name="connect-udp-h2"`,
		`transport_mode="connect_udp"`,
		`http_layer="h2"`,
		`tcp_transport="connect_stream"`,
	)
	requireSubstrings(t, smokeSrc, "in-proc prod-profile capsule smoke",
		"TestConnectUDPProdProfileH3CapsuleSmoke",
		"TestConnectUDPProdProfileH2CapsuleSmoke",
		`TransportMode:       option.MasqueTransportModeConnectUDP`,
		"connect-udp-h3-smoke",
		"connect-udp-h2-smoke",
	)
	requireSubstrings(t, gates, "L4 prod-profile capsule gate",
		"ProdProfileCapsule",
	)
}

// TestMasqueDockerBenchConnectIPH3TunKPIContract locks connect-ip-h3-tun docker thresholds and in-proc guard.
func TestMasqueDockerBenchConnectIPH3TunKPIContract(t *testing.T) {
	t.Parallel()
	runLocal := readDockerBenchSource(t, "run_local.py")
	history := readRepoSource(t, filepath.Join("docs", "masque", "bench-history", "2026-06-13-ingress-burst-wake-coalesce.md"))
	harnessSrc := readRepoSource(t, filepath.Join("hiddify-core", "hiddify-sing-box", "transport", "masque", "connectip_localize_harness.go"))
	uploadSrc := readRepoSource(t, filepath.Join("hiddify-core", "hiddify-sing-box", "transport", "masque", "connectip", "inttest", "localize_upload_gate_test.go"))

	requireSubstrings(t, runLocal, "connect-ip KPI thresholds",
		`BENCH_CONNECT_IP_MIN_UP_MBIT", "80"`,
		`BENCH_CONNECT_IP_MIN_DOWN_MBIT", "350"`,
		`BENCH_CONNECT_IP_TUN_DOD`,
		`BENCH_CONNECT_IP_TUN_PROD_MIN_MBIT`,
		`CONNECT_IP_MIN_DOWN = float(os.environ.get("BENCH_CONNECT_IP_MIN_DOWN_MBIT", "350"))`,
		`BENCH_CONNECT_IP_TUN_FAST_FAIL`,
		`run_connect_ip_tun_kpi`,
		`connect-ip-tun download TCP probe`,
		`connect-ip-tun download prime`,
		`connect-ip-tun: egress settle between legs`,
		`wait_connect_ip_native_l3_wired`,
		`connect_ip native L3 overlay wired`,
	)
	inboundSrc := readRepoSource(t, filepath.Join("hiddify-core", "hiddify-sing-box", "protocol", "tun", "l3_overlay_native_inbound.go"))
	tunL3Src := readRepoSource(t, filepath.Join("hiddify-core", "hiddify-sing-box", "protocol", "masque", "connect_ip_tun_l3.go"))
	requireSubstrings(t, inboundSrc, "PROD-1 native L3 resolve",
		"resolveL3OverlayNativeOutbound",
		"tryWireNativeConnectIPL3",
	)
	requireSubstrings(t, tunL3Src, "PROD-1 endpoint wire API",
		"WireConnectIPNativeL3",
		"L3OverlayNativeOutbound",
	)
	requireSubstrings(t, history, "connect-ip-h3-tun baseline",
		"connect-ip-h3-tun",
		"**104**",
		"**786**",
		"down ≥ 350",
	)
	requireSubstrings(t, harnessSrc, "in-proc docker KPI guard constants",
		"connectIPLocalizeFastMbps",
	)
	requireSubstrings(t, uploadSrc, "in-proc docker KPI guard test",
		"TestConnectIPDockerTUNKPIInProcGuard",
	)
	if dockerBenchConnectIPMinUpMbit != 80.0 || dockerBenchConnectIPMinDownMbit != 350.0 {
		t.Fatalf("connect-ip docker KPI constants up=%v down=%v want 80/350",
			dockerBenchConnectIPMinUpMbit, dockerBenchConnectIPMinDownMbit)
	}
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
	h2DrainGo := readRepoSource(t, filepath.Join("hiddify-core", "hiddify-sing-box", "transport", "masque", "stream", "conn", "paths.go"))
	requireSubstrings(t, h2DrainGo, "h2 bidi drain prod",
		"maybeStartDownloadDrain",
		"runDownloadDrain",
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

// TestMasqueDockerBenchRemoteComposeZeroEnvContract locks field remote client compose:
// no perf MASQUE knobs (hardcoded in Go); bench skip only.
func TestMasqueDockerBenchRemoteComposeZeroEnvContract(t *testing.T) {
	t.Parallel()
	remote := readDockerBenchSource(t, "docker-compose.remote.yml")
	forbidden := []string{
		"HIDDIFY_MASQUE_",
		"MASQUE_QUIC_KEEPALIVE_MS",
		"MASQUE_QUIC_HANDSHAKE_IDLE_MS",
		"MASQUE_CONNECT_STREAM_DIAL_MAX_ATTEMPTS",
		"MASQUE_CONNECT_STREAM_DIAL_BACKOFF_MS",
		"MASQUE_QUIC_PACKET_CONN_POLICY",
		"MASQUE_TRACE_RELAY_FLUSH",
		"MASQUE_H3_",
		"MASQUE_H2_",
		"MASQUE_RELAY_",
	}
	for _, key := range forbidden {
		if strings.Contains(remote, key) {
			t.Fatalf("docker-compose.remote.yml: forbidden perf env passthrough %q", key)
		}
	}
	requireSubstrings(t, remote, "remote compose zero-env",
		"MASQUE_BENCH_SKIP_URL_TEST",
		"QUIC_GO_DISABLE_GSO",
	)
}
