package ray2sing

import (
	"testing"

	T "github.com/sagernet/sing-box/option"
)

func TestUniquifyShareTags(t *testing.T) {
	outbounds := []T.Outbound{
		{Tag: "pathology"},
		{Tag: "pathology"},
		{Tag: "wg"},
	}
	uniquifyShareTags(outbounds, nil)
	if outbounds[0].Tag != "pathology" {
		t.Fatalf("first=%q want pathology", outbounds[0].Tag)
	}
	if outbounds[1].Tag != "pathology-1" {
		t.Fatalf("second=%q want pathology-1", outbounds[1].Tag)
	}
	if outbounds[2].Tag != "wg" {
		t.Fatalf("third=%q want wg", outbounds[2].Tag)
	}
}

func TestUniquifyShareTagsStripsLegacySection(t *testing.T) {
	outbounds := []T.Outbound{
		{Tag: "pathology § 0"},
		{Tag: "pathology § 1"},
	}
	uniquifyShareTags(outbounds, nil)
	if outbounds[0].Tag != "pathology" {
		t.Fatalf("first=%q", outbounds[0].Tag)
	}
	if outbounds[1].Tag != "pathology-1" {
		t.Fatalf("second=%q", outbounds[1].Tag)
	}
}
