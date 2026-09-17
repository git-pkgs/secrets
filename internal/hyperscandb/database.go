//go:build gohs

package hyperscandb

import (
	"crypto/sha256"
	"fmt"
	"io"
	"sort"

	"github.com/betterleaks/betterleaks/config"
	"github.com/flier/gohs/hyperscan"
)

type Stats struct {
	Exact     int
	Prefilter int
	Locators  int
}

var locatorRuleIDs = []string{"generic-api-key"}

const databaseFormat = "hyperscandb-v2"

func Compile(cfg *config.Config) (hyperscan.BlockDatabase, Stats, error) {
	ids := RuleIDs(cfg)

	patterns := make([]*hyperscan.Pattern, 0, len(ids))
	var stats Stats
	for _, id := range ids {
		rule := cfg.Rules[id]
		pattern := hyperscan.NewPattern(rule.Regex.String(), hyperscan.SingleMatch|hyperscan.AllowEmpty)
		testDB, testErr := hyperscan.NewBlockDatabase(pattern)
		if testErr == nil {
			_ = testDB.Close()
			stats.Exact++
		} else {
			pattern = hyperscan.NewPattern(rule.Regex.String(),
				hyperscan.DotAll|hyperscan.SingleMatch|hyperscan.AllowEmpty|hyperscan.PrefilterMode)
			stats.Prefilter++
		}
		pattern.Id = len(patterns)
		if !pattern.IsValid() {
			return nil, Stats{}, fmt.Errorf("rule %s: hyperscan rejects %q", id, rule.Regex.String())
		}
		patterns = append(patterns, pattern)
	}
	for _, id := range locatorRuleIDs {
		rule, ok := cfg.Rules[id]
		if !ok || rule.Regex == nil {
			return nil, Stats{}, fmt.Errorf("locator rule %s is missing", id)
		}
		pattern := hyperscan.NewPattern(rule.Regex.String(), hyperscan.AllowEmpty)
		pattern.Id = len(patterns)
		testDB, err := hyperscan.NewBlockDatabase(pattern)
		if err != nil {
			pattern = hyperscan.NewPattern(rule.Regex.String(), hyperscan.DotAll|hyperscan.AllowEmpty|hyperscan.PrefilterMode)
			pattern.Id = len(patterns)
			if !pattern.IsValid() {
				return nil, Stats{}, fmt.Errorf("locator rule %s: hyperscan rejects %q", id, rule.Regex.String())
			}
		} else {
			_ = testDB.Close()
		}
		patterns = append(patterns, pattern)
		stats.Locators++
	}
	if len(patterns) == 0 {
		return nil, Stats{}, fmt.Errorf("no rule regexes to compile")
	}
	db, err := hyperscan.NewBlockDatabase(patterns...)
	if err != nil {
		return nil, Stats{}, fmt.Errorf("compile hyperscan database: %w", err)
	}
	return db, stats, nil
}

func RuleIDs(cfg *config.Config) []string {
	ids := make([]string, 0, len(cfg.Rules))
	for id, rule := range cfg.Rules {
		if rule.Regex != nil {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	return ids
}

func LocatorRuleIDs() []string {
	return append([]string(nil), locatorRuleIDs...)
}

func Hash(cfg *config.Config) string {
	h := sha256.New()
	_, _ = io.WriteString(h, databaseFormat+"\n")
	for _, id := range RuleIDs(cfg) {
		_, _ = io.WriteString(h, id+"\x00"+cfg.Rules[id].Regex.String()+"\n")
	}
	for _, id := range locatorRuleIDs {
		_, _ = io.WriteString(h, "locator\x00"+id+"\n")
	}
	return fmt.Sprintf("%x", h.Sum(nil))
}
