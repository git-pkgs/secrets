package main

import (
	"bytes"
	"compress/gzip"
	"flag"
	"fmt"
	"os"

	"github.com/git-pkgs/secrets/betterleaks/config"
	"github.com/git-pkgs/secrets/internal/scandb"
)

const databaseFileMode = 0o644

func main() {
	output := flag.String("output", "scan.db.gz", "output compiled database path")
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
	db, err := scandb.Compile(cfg, true)
	if err != nil {
		return err
	}
	data, err := db.Marshal()
	if err != nil {
		return err
	}
	compressedSize, err := writeCompressedDatabase(output, data)
	if err != nil {
		return err
	}
	if err := os.WriteFile(output+".sha256", []byte(scandb.Hash(cfg, true)+"\n"), databaseFileMode); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "genscandb: %d rules, %d locators, %d bytes compressed from %d\n", len(scandb.RuleIDs(cfg)), len(scandb.LocatorRuleIDs(cfg, true)), compressedSize, len(data))
	return nil
}

func writeCompressedDatabase(output string, data []byte) (int, error) {
	var compressed bytes.Buffer
	writer, err := gzip.NewWriterLevel(&compressed, gzip.BestCompression)
	if err != nil {
		return 0, err
	}
	if _, err := writer.Write(data); err != nil {
		return 0, err
	}
	if err := writer.Close(); err != nil {
		return 0, err
	}
	if err := os.WriteFile(output, compressed.Bytes(), databaseFileMode); err != nil {
		return 0, err
	}
	return compressed.Len(), nil
}
