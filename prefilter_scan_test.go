//go:build !gohs

package main

import (
	"context"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/betterleaks/betterleaks/config"
	"github.com/betterleaks/betterleaks/detect"
	"github.com/betterleaks/betterleaks/report"
	"github.com/betterleaks/betterleaks/sources"
	"github.com/git-pkgs/secrets/internal/scandb"
)

func TestEmbeddedScanDatabaseMatchesRules(t *testing.T) {
	configureRegexpEngine()
	cfg, err := config.Default()
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(embeddedScanHash) != scandb.Hash(cfg) {
		t.Fatal("embedded database is stale; run go generate .")
	}
	pf, err := newPrefilter(cfg)
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
		if len(want) > 0 && (!candidate || !pf.match([]byte(text))) {
			t.Fatal("positive input was rejected")
		}
	}
	if pf.match([]byte("hello")) {
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
	pf, err := newPrefilter(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if pf.engine() != "scan-compiled" {
		t.Fatalf("engine=%q", pf.engine())
	}
	if !pf.match([]byte("CUSTOM_12345678")) || pf.match([]byte("CUSTOM_bad")) {
		t.Fatal("custom rule matching failed")
	}
	detector := detect.NewDetectorContext(context.Background(), cfg, detect.ValidationOptions{})
	findings, candidate := pf.detect(context.Background(), detector, []byte("CUSTOM_12345678"), nil)
	if !candidate || len(findings) != 1 || findings[0].RuleID != "custom-token" {
		t.Fatalf("candidate=%v findings=%v", candidate, findingKeys(findings))
	}
}

func TestDefaultCLIUsesEmbeddedScanDatabase(t *testing.T) {
	repo := repository(t)
	commitFile(t, repo, "config.yml", "token: "+fakeGitHubPAT+"\n", "add fixture")
	stdout, stderr := cliSplitFindings(t, "scan", repo, "--format=json", "--attribute=false")
	if !strings.Contains(stderr, "prefilter scan-embedded") {
		t.Fatalf("wrong backend: %s", stderr)
	}
	found := false
	for _, finding := range parseJSONFindings(t, stdout) {
		found = found || strings.Contains(finding.Rule, "github")
	}
	if !found {
		t.Fatalf("GitHub finding missing: %s", stdout)
	}
}

func TestDefaultCLIRejectsCleanBlob(t *testing.T) {
	repo := repository(t)
	commitFile(t, repo, "main.go", "package main\nfunc main() {}\n", "add source")
	stdout, stderr := cliSplit(t, "scan", repo, "--format=json", "--attribute=false")
	if !strings.Contains(stderr, "prefilter scan-embedded") || len(parseJSONFindings(t, stdout)) != 0 {
		t.Fatalf("unexpected scan output: stdout=%q stderr=%q", stdout, stderr)
	}
}
