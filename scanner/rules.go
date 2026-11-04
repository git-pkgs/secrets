package scanner

import "github.com/git-pkgs/secrets/betterleaks/config"

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
