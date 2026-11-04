//go:build !gohs

package main

import (
	"strings"
	"testing"
)

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
