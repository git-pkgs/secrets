//go:build gohs

package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/betterleaks/betterleaks/config"
	"github.com/git-pkgs/secrets/internal/hyperscandb"
)

func main() {
	output := flag.String("output", "hyperscan.db", "output database path")
	hashOutput := flag.String("hash-output", "", "output rule hash path (default: <output>.sha256)")
	flag.Parse()

	cfg, err := config.Default()
	if err != nil {
		fail(err)
	}
	db, stats, err := hyperscandb.Compile(cfg)
	if err != nil {
		fail(err)
	}
	defer func() { _ = db.Close() }()
	data, err := db.Marshal()
	if err != nil {
		fail(fmt.Errorf("serialize hyperscan database: %w", err))
	}
	if err := os.WriteFile(*output, data, 0o644); err != nil {
		fail(err)
	}
	if *hashOutput == "" {
		*hashOutput = *output + ".sha256"
	}
	if err := os.WriteFile(*hashOutput, []byte(hyperscandb.Hash(cfg)+"\n"), 0o644); err != nil {
		fail(err)
	}
	fmt.Fprintf(os.Stderr, "genhsdb: %d exact patterns, %d prefilter patterns, %d locators\n", stats.Exact, stats.Prefilter, stats.Locators)
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "genhsdb:", err)
	os.Exit(1)
}
