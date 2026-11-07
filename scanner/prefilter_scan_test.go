//go:build !gohs

package scanner

import (
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/git-pkgs/scan"
	"github.com/git-pkgs/secrets/betterleaks/config"
	"github.com/git-pkgs/secrets/betterleaks/detect"
	"github.com/git-pkgs/secrets/betterleaks/report"
	"github.com/git-pkgs/secrets/betterleaks/sources"
	"github.com/git-pkgs/secrets/internal/scandb"
)

func BenchmarkEmbeddedScanDatabaseLoad(b *testing.B) {
	reader, err := gzip.NewReader(bytes.NewReader(embeddedScanDB))
	if err != nil {
		b.Fatal(err)
	}
	data, err := io.ReadAll(reader)
	if err != nil {
		b.Fatal(err)
	}
	if err := reader.Close(); err != nil {
		b.Fatal(err)
	}
	b.Run("compressed", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			if _, err := unmarshalCompressedDatabase(embeddedScanDB); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("uncompressed", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			if _, err := scan.UnmarshalDatabase(data); err != nil {
				b.Fatal(err)
			}
		}
	})
}

func TestEmbeddedScanDatabaseMatchesRules(t *testing.T) {
	cfg, err := config.Default()
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(embeddedScanHash) != scandb.Hash(cfg, true) {
		t.Fatal("embedded database is stale; run go generate ./scanner")
	}
	pf, err := newPrefilter(cfg, true)
	if err != nil {
		t.Fatal(err)
	}
	if pf.engine() != "scan-embedded" {
		t.Fatalf("engine=%q", pf.engine())
	}
	if got, want := pf.db.Stats().Patterns, len(pf.ruleIDs)+len(pf.locatorIDs); got != want {
		t.Fatalf("patterns=%d, want %d", got, want)
	}
	detector := detect.NewDetectorContext(context.Background(), cfg, detect.ValidationOptions{})
	for _, text := range []string{
		"package main\nfunc main() {}\n",
		"token: " + fakeGitHubPAT + "\n",
		"api_key = \"Z7mQ2vN9xK4pR8sT6wY3cF5hJ1dL0bGa\"\n" + strings.Repeat("ordinary text\n", 100) + "auth_token = \"H4nC8qW1zM6rT9vB2kP7xD5sJ0fL3aYe\"\n",
	} {
		fragment := sources.Fragment{Raw: text}
		want := detector.DetectFragment(context.Background(), fragment)
		got, candidate := pf.detect(context.Background(), detector, []byte(text), nil)
		if !reflect.DeepEqual(findingKeys(got), findingKeys(want)) {
			t.Fatalf("prefilter=%v detector=%v", findingKeys(got), findingKeys(want))
		}
		if len(want) > 0 && !candidate {
			t.Fatal("positive input was rejected")
		}
	}
	if findings, candidate := pf.detect(context.Background(), detector, []byte("hello"), nil); candidate || len(findings) > 0 {
		t.Fatal("negative input was accepted")
	}
}

func findingKeys(findings []report.Finding) []string {
	var keys []string
	for _, finding := range findings {
		keys = append(keys, finding.RuleID+"\x00"+finding.Secret)
	}
	sort.Strings(keys)
	return keys
}

func TestScanPrefilterCustomRules(t *testing.T) {
	cfg, err := config.ParseTOMLString(`[[rules]]
id = "custom-token"
description = "Fixture token"
regex = 'CUSTOM_[0-9]{8}'
keywords = ["CUSTOM_"]
`, "fixture.toml")
	if err != nil {
		t.Fatal(err)
	}
	pf, err := newPrefilter(cfg, false)
	if err != nil {
		t.Fatal(err)
	}
	if pf.engine() != "scan-compiled" {
		t.Fatalf("engine=%q", pf.engine())
	}
	detector := detect.NewDetectorContext(context.Background(), cfg, detect.ValidationOptions{})
	findings, candidate := pf.detect(context.Background(), detector, []byte("CUSTOM_12345678"), nil)
	if !candidate || len(findings) != 1 || findings[0].RuleID != "custom-token" {
		t.Fatalf("candidate=%v findings=%v", candidate, findingKeys(findings))
	}
}
