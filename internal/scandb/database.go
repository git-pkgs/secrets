package scandb

import (
	"crypto/sha256"
	"fmt"
	"io"
	"sort"

	"github.com/betterleaks/betterleaks/config"
	"github.com/git-pkgs/scan"
)

const databaseFormat = "scandb-v1"

func RuleIDs(cfg *config.Config) []string {
	var ids []string
	for id, rule := range cfg.Rules {
		if rule.Regex != nil {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	return ids
}

func LocatorRuleIDs(cfg *config.Config) []string {
	if rule, ok := cfg.Rules["generic-api-key"]; ok && rule.Regex != nil {
		return []string{"generic-api-key"}
	}
	return nil
}

func Compile(cfg *config.Config) (*scan.Database, error) {
	ids := RuleIDs(cfg)
	patterns := make([]*scan.Pattern, 0, len(ids)+1)
	for _, id := range ids {
		patterns = append(patterns, &scan.Pattern{Expression: cfg.Rules[id].Regex.String(), ID: uint(len(patterns)), Flags: scan.SingleMatch | scan.AllowEmpty})
	}
	for _, id := range LocatorRuleIDs(cfg) {
		patterns = append(patterns, &scan.Pattern{Expression: cfg.Rules[id].Regex.String(), ID: uint(len(patterns)), Flags: scan.AllowEmpty})
	}
	if len(patterns) == 0 {
		return nil, nil
	}
	return scan.Compile(patterns...)
}

func Hash(cfg *config.Config) string {
	h := sha256.New()
	_, _ = io.WriteString(h, databaseFormat+"\n")
	for _, id := range RuleIDs(cfg) {
		_, _ = io.WriteString(h, id+"\x00"+cfg.Rules[id].Regex.String()+"\n")
	}
	for _, id := range LocatorRuleIDs(cfg) {
		_, _ = io.WriteString(h, "locator\x00"+id+"\n")
	}
	return fmt.Sprintf("%x", h.Sum(nil))
}
