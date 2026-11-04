package main

import (
	"fmt"
	"os"
	"sort"

	"github.com/git-pkgs/secrets/betterleaks/config"
)

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
