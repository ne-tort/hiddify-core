package config

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/common/srs"
	"github.com/sagernet/sing-box/option"
)

func repoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	// .../hiddify-core/v2/config
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", ".."))
}

func readSRS(t *testing.T, path string) option.PlainRuleSetCompat {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	head := make([]byte, 3)
	if _, err := f.Read(head); err != nil {
		t.Fatal(err)
	}
	if string(head) != "SRS" {
		t.Fatalf("bad magic %q at %s", head, path)
	}

	if _, err := f.Seek(0, 0); err != nil {
		t.Fatal(err)
	}
	rs, err := srs.Read(f, true)
	if err != nil {
		t.Fatalf("srs.Read %s: %v", path, err)
	}
	return rs
}

func countDomains(rules []option.HeadlessRule) int {
	n := 0
	for _, r := range rules {
		switch r.Type {
		case C.RuleTypeDefault:
			n += len(r.DefaultOptions.Domain)
			n += len(r.DefaultOptions.DomainSuffix)
			n += len(r.DefaultOptions.DomainKeyword)
			n += len(r.DefaultOptions.DomainRegex)
			n += len(r.DefaultOptions.AdGuardDomain)
		case C.RuleTypeLogical:
			n += countDomains(r.LogicalOptions.Rules)
		}
	}
	return n
}

func writeSRS(t *testing.T, rs option.PlainRuleSet, version uint8) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := srs.Write(&buf, rs, version); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestHiddifyAdsRulesetFormat(t *testing.T) {
	root := repoRoot(t)
	path := filepath.Join(root, "rules", "ads", "hiddify-ads.srs")
	info, err := os.Stat(path)
	if err != nil {
		t.Skip("bundled rules/ads/hiddify-ads.srs missing:", err)
	}

	rs := readSRS(t, path)
	if rs.Version == 0 {
		t.Fatal("version=0")
	}
	if len(rs.Options.Rules) == 0 {
		t.Fatal("empty rules")
	}
	domains := countDomains(rs.Options.Rules)
	t.Logf("file=%s size=%d version=%d rules=%d domains=%d",
		path, info.Size(), rs.Version, len(rs.Options.Rules), domains)

	if info.Size() > 512*1024 {
		t.Fatalf("suspicious size %d (>512KB)", info.Size())
	}
	if domains < 100 {
		t.Fatalf("suspiciously few domains: %d", domains)
	}
}

func TestHiddifyAdsMatchesUpstream(t *testing.T) {
	root := repoRoot(t)
	local := filepath.Join(root, "rules", "ads", "hiddify-ads.srs")
	tmp := filepath.Join(root, "_tmp", "ads-test", "geosite-category-ads-all.srs")
	if _, err := os.Stat(local); err != nil {
		t.Skip("local srs missing")
	}
	if _, err := os.Stat(tmp); err != nil {
		t.Skip("upstream sample missing (run ads size fetch first):", err)
	}
	localBytes, err := os.ReadFile(local)
	if err != nil {
		t.Fatal(err)
	}
	upstreamBytes, err := os.ReadFile(tmp)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(localBytes, upstreamBytes) {
		t.Fatalf("local != upstream (local=%d upstream=%d)", len(localBytes), len(upstreamBytes))
	}
}

func TestNaiveMergeVsSingleRuleset(t *testing.T) {
	root := repoRoot(t)
	dir := filepath.Join(root, "_tmp", "ads-test")
	allPath := filepath.Join(dir, "geosite-category-ads-all.srs")
	subPath := filepath.Join(dir, "geosite-category-ads.srs")
	if _, err := os.Stat(allPath); err != nil {
		t.Skip("sample srs missing")
	}
	if _, err := os.Stat(subPath); err != nil {
		t.Skip("sample srs missing")
	}

	all := readSRS(t, allPath)
	sub := readSRS(t, subPath)

	allDomains := countDomains(all.Options.Rules)
	subDomains := countDomains(sub.Options.Rules)

	naive := option.PlainRuleSet{
		Rules: append(append([]option.HeadlessRule{}, all.Options.Rules...), sub.Options.Rules...),
	}
	naiveBytes := writeSRS(t, naive, all.Version)

	t.Logf("ads-all: rules=%d domains=%d size=%d",
		len(all.Options.Rules), allDomains, mustFileSize(t, allPath))
	t.Logf("ads: rules=%d domains=%d size=%d",
		len(sub.Options.Rules), subDomains, mustFileSize(t, subPath))
	t.Logf("naive merge (no dedup): rules=%d size=%d", len(naive.Rules), len(naiveBytes))

	if len(naiveBytes) <= mustFileSize(t, allPath) {
		t.Fatalf("expected naive merge to grow file size")
	}
	if allDomains < subDomains {
		t.Fatalf("ads-all should cover at least ads subset domains")
	}
	// Using category-ads-all alone avoids redundant merge; dedup in CI would matter
	// when combining multiple independent sources, not this subset pair.
}

func TestBuildConfigInjectsAdsBlock(t *testing.T) {
	root := repoRoot(t)
	srsPath := filepath.Join(root, "rules", "ads", "hiddify-ads.srs")
	if _, err := os.Stat(srsPath); err != nil {
		t.Skip("srs missing")
	}
	abs, err := filepath.Abs(srsPath)
	if err != nil {
		t.Fatal(err)
	}

	hopt := DefaultHiddifyOptions()
	hopt.BlockAds = true
	hopt.AdsRuleSetPath = abs

	var rulesets []option.RuleSet
	var rules []option.Rule
	appendAdsBlockRules(&rulesets, &rules, abs)

	if len(rulesets) != 1 || len(rulesets[0].Tag) != 1 || rulesets[0].Tag[0] != AdsRuleSetTag {
		t.Fatalf("rulesets=%+v", rulesets)
	}
	if len(rules) != 1 || rules[0].DefaultOptions.RuleAction.Action != C.RuleActionTypeReject {
		t.Fatalf("rules=%+v", rules)
	}
	_ = hopt
}

func mustFileSize(t *testing.T, path string) int {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return int(info.Size())
}
