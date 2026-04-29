// prints comma-separated -tags for local scripts (build_windows.bat) — single source: build_shared.CoreSingBox*Tags
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/hiddify/hiddify-core/cmd/internal/build_shared"
)

func main() {
	windows := flag.Bool("windows", false, "include with_purego for Windows (naive/cronet)")
	noNaive := flag.Bool("no-naive", false, "exclude with_naive_outbound (s-ui platforms without cronet/naive)")
	flag.Parse()

	tags := build_shared.CoreSingBoxBaseTags()
	if *windows {
		tags = build_shared.CoreSingBoxTagsWindows()
	}
	if *noNaive {
		tags = filterOut(tags, "with_naive_outbound")
	}
	_, _ = fmt.Fprint(os.Stdout, build_shared.JoinBuildTags(tags))
}

func filterOut(in []string, drop string) []string {
	var out []string
	for _, t := range in {
		if t != drop {
			out = append(out, t)
		}
	}
	return out
}
