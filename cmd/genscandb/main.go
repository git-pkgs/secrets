package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/betterleaks/betterleaks/config"
	"github.com/git-pkgs/secrets/internal/scandb"
)

const databaseFileMode = 0o644

func main() {
	output := flag.String("output", "scan.db", "output compiled database path")
	flag.Parse()
	if err := generate(*output); err != nil {
		fmt.Fprintln(os.Stderr, "genscandb:", err)
		os.Exit(1)
	}
}

func generate(output string) error {
	cfg, err := config.Default()
	if err != nil {
		return err
	}
	db, err := scandb.Compile(cfg)
	if err != nil {
		return err
	}
	data, err := db.Marshal()
	if err != nil {
		return err
	}
	if err := os.WriteFile(output, data, databaseFileMode); err != nil {
		return err
	}
	if err := os.WriteFile(output+".sha256", []byte(scandb.Hash(cfg)+"\n"), databaseFileMode); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "genscandb: %d rules, %d locators, %d bytes\n", len(scandb.RuleIDs(cfg)), len(scandb.LocatorRuleIDs(cfg)), len(data))
	return nil
}
