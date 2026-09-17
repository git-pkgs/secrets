package main

import (
	"fmt"
	"os"
	"sort"

	"github.com/betterleaks/betterleaks/config"
)

func configuredPathOnlyRules(cfg *config.Config) []config.Rule {
	var rules []config.Rule
	for _, ruleID := range cfg.OrderedRules {
		rule := cfg.Rules[ruleID]
		if rule.Regex == nil && rule.Path != nil {
			rules = append(rules, rule)
		}
	}
	return rules
}

func matchesPathOnlyRule(rules []config.Rule, path string) bool {
	if path == "" {
		return false
	}
	for _, rule := range rules {
		if rule.Path.MatchString(path) {
			return true
		}
	}
	return false
}

func rulesCmd() error {
	cfg, err := config.Default()
	if err != nil {
		return err
	}
	ids := make([]string, 0, len(cfg.Rules))
	for id := range cfg.Rules {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		r := cfg.Rules[id]
		if _, err := fmt.Fprintf(os.Stdout, "%s\t%s\n", id, r.Description); err != nil {
			return err
		}
	}
	_, err = fmt.Fprintf(os.Stderr, "secrets: %d rules\n", len(ids))
	return err
}
