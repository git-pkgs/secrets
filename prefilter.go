//go:build !gohs && !scan

package main

import (
	"context"

	"github.com/betterleaks/betterleaks/config"
	"github.com/betterleaks/betterleaks/detect"
	"github.com/betterleaks/betterleaks/report"
	"github.com/betterleaks/betterleaks/sources"
)

// prefilter cheaply rejects blobs that cannot match any rule. Without the
// gohs build tag it accepts everything and relies on the detector's own
// aho-corasick keyword pass.
type prefilter struct {
	pathOnlyRules []config.Rule
}

func newPrefilter(cfg *config.Config) (prefilter, error) {
	return prefilter{pathOnlyRules: configuredPathOnlyRules(cfg)}, nil
}

func (prefilter) match([]byte) bool { return true }

func (p prefilter) pathMatch(path string) bool {
	return matchesPathOnlyRule(p.pathOnlyRules, path)
}

func (prefilter) detect(ctx context.Context, d *detect.Detector, data []byte, attributes map[string]string) ([]report.Finding, bool) {
	return d.DetectFragment(ctx, sources.Fragment{
		Raw: string(data), Attributes: attributes,
	}), true
}

func (prefilter) engine() string { return "none" }
