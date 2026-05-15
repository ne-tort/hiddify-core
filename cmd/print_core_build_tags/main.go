// Печатает CSV build tags для sing-box / hiddify-core (stdout одной строкой).
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/hiddify/hiddify-core/cmd/internal/build_shared"
)

func main() {
	windows := flag.Bool("windows", false, "tags for Windows client (with_purego)")
	noNaive := flag.Bool("no-naive", false, "omit with_naive_outbound")
	flag.Parse()

	var tags []string
	if *windows {
		tags = build_shared.CoreSingBoxTagsWindows()
	} else {
		tags = build_shared.CoreSingBoxBaseTags()
		if !*noNaive {
			tags = append(tags, "with_naive_outbound")
		}
	}

	if *noNaive {
		out := make([]string, 0, len(tags))
		for _, t := range tags {
			if t != "with_naive_outbound" {
				out = append(out, t)
			}
		}
		tags = out
	}

	fmt.Fprintln(os.Stdout, strings.TrimSpace(build_shared.JoinBuildTags(tags)))
}
