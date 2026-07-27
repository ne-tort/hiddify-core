package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/common/srs"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
)

type entry struct {
	Tag   string `json:"tag"`
	Count int    `json:"count"`
}

func main() {
	outDir := flag.String("out", "rules/tags", "output directory")
	assetsDir := flag.String("assets", "assets/core/tags", "bundled assets directory")
	workers := flag.Int("workers", 32, "parallel SRS download workers")
	flag.Parse()

	geosite, err := buildIndex(
		"https://api.github.com/repos/SagerNet/sing-geosite/git/trees/rule-set?recursive=1",
		"geosite-",
		"https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/",
		*workers,
	)
	if err != nil {
		fmt.Fprintf(os.Stderr, "geosite: %v\n", err)
		os.Exit(1)
	}
	geoip, err := buildIndex(
		"https://api.github.com/repos/SagerNet/sing-geoip/git/trees/rule-set?recursive=1",
		"geoip-",
		"https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/",
		*workers,
	)
	if err != nil {
		fmt.Fprintf(os.Stderr, "geoip: %v\n", err)
		os.Exit(1)
	}

	if err := os.MkdirAll(*outDir, 0o755); err != nil {
		panic(err)
	}
	if err := os.MkdirAll(*assetsDir, 0o755); err != nil {
		panic(err)
	}
	writeJSON(filepath.Join(*outDir, "geosite.json"), geosite)
	writeJSON(filepath.Join(*outDir, "geoip.json"), geoip)
	writeJSON(filepath.Join(*assetsDir, "geosite.json"), geosite)
	writeJSON(filepath.Join(*assetsDir, "geoip.json"), geoip)
	manifest := map[string]any{
		"version":     time.Now().UTC().Format("2006.01.02"),
		"geosite_url": "https://raw.githubusercontent.com/ne-tort/hiddify-app/main/rules/tags/geosite.json",
		"geoip_url":   "https://raw.githubusercontent.com/ne-tort/hiddify-app/main/rules/tags/geoip.json",
	}
	writeJSON(filepath.Join(*outDir, "manifest.json"), manifest)
	fmt.Printf("geosite=%d geoip=%d\n", len(geosite), len(geoip))
}

func buildIndex(treeURL, prefix, rawBase string, workers int) ([]entry, error) {
	req, err := http.NewRequest(http.MethodGet, treeURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "hiddify-geo-tags-index")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("status %d: %s", resp.StatusCode, body)
	}
	var tree struct {
		Tree []struct {
			Path string `json:"path"`
			Type string `json:"type"`
		} `json:"tree"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tree); err != nil {
		return nil, err
	}

	type job struct {
		tag string
		url string
	}
	var jobs []job
	for _, item := range tree.Tree {
		if item.Type != "blob" || !strings.HasPrefix(item.Path, prefix) || !strings.HasSuffix(item.Path, ".srs") {
			continue
		}
		tag := strings.TrimSuffix(strings.TrimPrefix(item.Path, prefix), ".srs")
		jobs = append(jobs, job{tag: tag, url: rawBase + item.Path})
	}

	if workers < 1 {
		workers = 1
	}
	client := &http.Client{Timeout: 30 * time.Second}
	out := make([]entry, len(jobs))
	var done atomic.Int32
	var wg sync.WaitGroup
	ch := make(chan int, workers)
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range ch {
				count := 0
				if r, err := client.Get(jobs[i].url); err == nil {
					if r.StatusCode == 200 {
						if rs, err := srs.Read(r.Body, true); err == nil {
							count = countEntries(rs.Options.Rules)
						}
					}
					r.Body.Close()
				}
				out[i] = entry{Tag: jobs[i].tag, Count: count}
				n := done.Add(1)
				if n%200 == 0 || int(n) == len(jobs) {
					fmt.Fprintf(os.Stderr, "%s progress %d/%d\n", prefix, n, len(jobs))
				}
			}
		}()
	}
	for i := range jobs {
		ch <- i
	}
	close(ch)
	wg.Wait()

	sort.Slice(out, func(i, j int) bool { return out[i].Tag < out[j].Tag })
	return out, nil
}

func countEntries(rules []option.HeadlessRule) int {
	n := 0
	for _, r := range rules {
		switch r.Type {
		case C.RuleTypeDefault:
			n += len(r.DefaultOptions.Domain)
			n += len(r.DefaultOptions.DomainSuffix)
			n += len(r.DefaultOptions.DomainKeyword)
			n += len(r.DefaultOptions.DomainRegex)
			n += len(r.DefaultOptions.AdGuardDomain)
			n += len(r.DefaultOptions.IPCIDR)
		case C.RuleTypeLogical:
			n += countEntries(r.LogicalOptions.Rules)
		}
	}
	return n
}

func writeJSON(path string, v any) {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		panic(err)
	}
	if err := os.WriteFile(path, append(b, '\n'), 0o644); err != nil {
		panic(err)
	}
}
