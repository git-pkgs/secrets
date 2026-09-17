//go:build gohs

package main

import (
	"strings"
	"testing"

	"github.com/betterleaks/betterleaks/config"
	"github.com/git-pkgs/secrets/internal/hyperscandb"
)

func TestEmbeddedHyperscanDatabaseMatchesRules(t *testing.T) {
	cfg, err := config.Default()
	if err != nil {
		t.Fatal(err)
	}
	if got, want := strings.TrimSpace(embeddedHyperscanHash), hyperscandb.Hash(cfg); got != want {
		t.Fatalf("embedded database hash %q, want %q; run go generate -tags gohs .", got, want)
	}
}
