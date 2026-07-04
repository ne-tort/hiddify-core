package build_shared

import (
	"slices"
	"testing"
)

func TestCoreSingBoxBaseTagsIncludesMasque(t *testing.T) {
	t.Parallel()
	if !slices.Contains(CoreSingBoxBaseTags(), "with_masque") {
		t.Fatal("CoreSingBoxBaseTags must include with_masque for prod MASQUE endpoint")
	}
}

func TestCoreSingBoxTagsWindowsIncludesMasque(t *testing.T) {
	t.Parallel()
	if !slices.Contains(CoreSingBoxTagsWindows(), "with_masque") {
		t.Fatal("CoreSingBoxTagsWindows must include with_masque")
	}
}
