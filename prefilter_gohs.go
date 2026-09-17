//go:build gohs

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
	"github.com/flier/gohs/hyperscan"
	"github.com/git-pkgs/secrets/internal/hyperscandb"
)

//go:generate go run -tags gohs ./cmd/genhsdb -output hyperscan.db

//go:embed hyperscan.db
var embeddedHyperscanDB []byte

//go:embed hyperscan.db.sha256
var embeddedHyperscanHash string

// prefilter compiles every rule regex into a single vectorscan block
// database. A blob is passed to the full detector only if at least one
// pattern matches somewhere. PrefilterMode lets hyperscan approximate
// constructs it does not support natively, at the cost of possible false
// positives, which is acceptable since the full detector confirms hits.
type prefilter struct {
	db            hyperscan.BlockDatabase
	pool          *sync.Pool
	engineName    string
	ruleIDs       []string
	locatorIDs    []string
	pathOnlyRules []config.Rule
}

func newPrefilter(cfg *config.Config) (prefilter, error) {
	var db hyperscan.BlockDatabase
	var err error
	engineName := "hyperscan-compiled"
	if strings.TrimSpace(embeddedHyperscanHash) == hyperscandb.Hash(cfg) {
		db, err = hyperscan.UnmarshalBlockDatabase(embeddedHyperscanDB)
		if err == nil {
			engineName = "hyperscan-embedded"
		}
	}
	if db == nil {
		db, _, err = hyperscandb.Compile(cfg)
		if err != nil {
			return prefilter{}, err
		}
	}
	pool := &sync.Pool{New: func() any {
		s, err := hyperscan.NewScratch(db)
		if err != nil {
			panic(err)
		}
		return s
	}}
	return prefilter{
		db: db, pool: pool, engineName: engineName,
		ruleIDs: hyperscandb.RuleIDs(cfg), locatorIDs: hyperscandb.LocatorRuleIDs(),
		pathOnlyRules: configuredPathOnlyRules(cfg),
	}, nil
}

func (p prefilter) match(data []byte) bool {
	if p.db == nil {
		return true
	}
	scratch := p.pool.Get().(*hyperscan.Scratch)
	defer p.pool.Put(scratch)
	hit := false
	err := p.db.Scan(data, scratch, func(uint, uint64, uint64, uint, interface{}) error {
		hit = true
		return hyperscan.ErrScanTerminated
	}, nil)
	return hit || err != nil
}

func (p prefilter) pathMatch(path string) bool {
	return matchesPathOnlyRule(p.pathOnlyRules, path)
}

func (p prefilter) detect(ctx context.Context, d *detect.Detector, data []byte, attributes map[string]string) ([]report.Finding, bool) {
	fragment := sources.Fragment{Raw: string(data), Attributes: attributes}
	if p.db == nil {
		return d.DetectFragment(ctx, fragment), true
	}
	scratch := p.pool.Get().(*hyperscan.Scratch)
	defer p.pool.Put(scratch)
	var ids []string
	seen := make([]bool, len(p.ruleIDs))
	locations := make(map[string][]byteRange)
	err := p.db.Scan(data, scratch, func(id uint, _ uint64, to uint64, _ uint, _ interface{}) error {
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
			start := max(int(to)-padding, 0)
			end := min(int(to)+padding, len(data))
			locations[ruleID] = append(locations[ruleID], byteRange{start: start, end: end})
		}
		return nil
	}, nil)
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
