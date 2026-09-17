//go:build scan && !gohs

package main

import (
	"context"
	_ "embed"
	"strings"
	"sync"

	"github.com/betterleaks/betterleaks/config"
	"github.com/betterleaks/betterleaks/detect"
	"github.com/betterleaks/betterleaks/report"
	"github.com/betterleaks/betterleaks/sources"
	"github.com/git-pkgs/scan"
	"github.com/git-pkgs/secrets/internal/scandb"
)

//go:generate go run ./cmd/genscandb -output scan.db

//go:embed scan.db
var embeddedScanDB []byte

//go:embed scan.db.sha256
var embeddedScanHash string

type prefilter struct {
	db            *scan.Database
	pool          *sync.Pool
	engineName    string
	ruleIDs       []string
	locatorIDs    []string
	pathOnlyRules []config.Rule
}

func newPrefilter(cfg *config.Config) (prefilter, error) {
	var db *scan.Database
	var err error
	engineName := "scan-compiled"
	if strings.TrimSpace(embeddedScanHash) == scandb.Hash(cfg) {
		db, err = scan.UnmarshalDatabase(embeddedScanDB)
		if err != nil {
			return prefilter{}, err
		}
		engineName = "scan-embedded"
	} else {
		db, err = scandb.Compile(cfg)
		if err != nil {
			return prefilter{}, err
		}
	}
	pool := &sync.Pool{New: func() any { return scan.NewScratch(db) }}
	return prefilter{db: db, pool: pool, engineName: engineName, ruleIDs: scandb.RuleIDs(cfg), locatorIDs: scandb.LocatorRuleIDs(cfg), pathOnlyRules: configuredPathOnlyRules(cfg)}, nil
}

func (p prefilter) match(data []byte) bool {
	if p.db == nil {
		return true
	}
	scratch := p.pool.Get().(*scan.Scratch)
	defer p.pool.Put(scratch)
	matched, err := p.db.Match(data, scratch)
	return matched || err != nil
}

func (p prefilter) pathMatch(path string) bool { return matchesPathOnlyRule(p.pathOnlyRules, path) }

func (p prefilter) detect(ctx context.Context, d *detect.Detector, data []byte, attributes map[string]string) ([]report.Finding, bool) {
	fragment := sources.Fragment{Raw: string(data), Attributes: attributes}
	if p.db == nil {
		return d.DetectFragment(ctx, fragment), true
	}
	scratch := p.pool.Get().(*scan.Scratch)
	defer p.pool.Put(scratch)
	var ids []string
	seen := make([]bool, len(p.ruleIDs))
	locations := make(map[string][]byteRange)
	err := p.db.Scan(data, scratch, func(match scan.Match) error {
		id, to := match.ID, match.To
		if int(id) < len(p.ruleIDs) {
			if !seen[id] {
				seen[id] = true
				ids = append(ids, p.ruleIDs[id])
			}
			return nil
		}
		locator := int(id) - len(p.ruleIDs)
		if locator >= 0 && locator < len(p.locatorIDs) && to <= uint64(len(data)) {
			ruleID := p.locatorIDs[locator]
			padding := locatorPadding(ruleID)
			locations[ruleID] = append(locations[ruleID], byteRange{start: max(int(to)-padding, 0), end: min(int(to)+padding, len(data))})
		}
		return nil
	})
	if err != nil {
		return d.DetectFragment(ctx, fragment), true
	}
	path := fragment.Attr(sources.AttrPath)
	for _, rule := range p.pathOnlyRules {
		if path != "" && rule.Path.MatchString(path) {
			ids = append(ids, rule.RuleID)
		}
	}
	if len(ids) == 0 {
		return nil, false
	}
	windows := make(map[string][]detect.RuleWindow, len(locations))
	for ruleID, ranges := range locations {
		windows[ruleID] = normalizeWindows(data, ranges)
	}
	return d.DetectFragmentRuleWindows(ctx, fragment, ids, windows), true
}

func (p prefilter) engine() string { return p.engineName }
