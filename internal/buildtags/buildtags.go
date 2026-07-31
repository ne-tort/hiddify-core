package buildtags

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
)

// Load reads hiddify-core/build_tags.txt (comma-separated tags, # comments).
// searchRoots are directories to walk upward from (typically module / executable dir).
func Load(searchRoots ...string) ([]string, error) {
	path, err := find(searchRoots...)
	if err != nil {
		return nil, err
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var line string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		raw := strings.TrimSpace(sc.Text())
		if raw == "" || strings.HasPrefix(raw, "#") {
			continue
		}
		line = raw
		break
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if line == "" {
		return nil, os.ErrNotExist
	}
	parts := strings.Split(line, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out, nil
}

func find(roots ...string) (string, error) {
	seen := map[string]struct{}{}
	var candidates []string
	for _, root := range roots {
		if root == "" {
			continue
		}
		dir, err := filepath.Abs(root)
		if err != nil {
			continue
		}
		for i := 0; i < 8; i++ {
			if _, ok := seen[dir]; ok {
				break
			}
			seen[dir] = struct{}{}
			candidates = append(candidates, filepath.Join(dir, "build_tags.txt"))
			parent := filepath.Dir(dir)
			if parent == dir {
				break
			}
			dir = parent
		}
	}
	wd, _ := os.Getwd()
	if wd != "" {
		candidates = append(candidates, filepath.Join(wd, "build_tags.txt"))
	}
	for _, c := range candidates {
		if st, err := os.Stat(c); err == nil && !st.IsDir() {
			return c, nil
		}
	}
	return "", os.ErrNotExist
}
