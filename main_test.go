package main

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"
	"unicode/utf16"

	"github.com/git-pkgs/sarif"
)

func TestMain(m *testing.M) {
	if os.Getenv("SECRETS_TEST_CLI") == "1" {
		main()
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func git(t *testing.T, repo string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", repo}, args...)...)
	cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_NOSYSTEM=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
}

func repository(t *testing.T) string {
	t.Helper()
	repo := t.TempDir()
	git(t, repo, "init", "-b", "main")
	git(t, repo, "config", "user.name", "Test")
	git(t, repo, "config", "user.email", "test@example.org")
	git(t, repo, "config", "commit.gpgsign", "false")
	return repo
}

func commitFile(t *testing.T, repo, name, content, subject string) {
	t.Helper()
	path := filepath.Join(repo, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	git(t, repo, "add", "--", name)
	git(t, repo, "commit", "-m", subject)
}

func encodedUTF16(content string, order binary.ByteOrder) string {
	units := utf16.Encode([]rune(content))
	data := make([]byte, 2+len(units)*2)
	if order == binary.LittleEndian {
		data[0], data[1] = 0xff, 0xfe
	} else {
		data[0], data[1] = 0xfe, 0xff
	}
	for i, unit := range units {
		order.PutUint16(data[2+i*2:], unit)
	}
	return string(data)
}

func cli(t *testing.T, args ...string) string {
	t.Helper()
	out, errOut := cliSplit(t, args...)
	return out + errOut
}

func cliSplit(t *testing.T, args ...string) (string, string) {
	t.Helper()
	stdout, stderr, code := cliResult(t, args...)
	if code != 0 {
		t.Fatalf("secrets %v: exit %d\n%s%s", args, code, stdout, stderr)
	}
	return stdout, stderr
}

func cliFindings(t *testing.T, args ...string) string {
	t.Helper()
	stdout, stderr := cliSplitFindings(t, args...)
	return stdout + stderr
}

func cliSplitFindings(t *testing.T, args ...string) (string, string) {
	t.Helper()
	stdout, stderr, code := cliResult(t, args...)
	if code != defaultFindingExitCode {
		t.Fatalf("secrets %v: exit %d, want %d\n%s%s", args, code, defaultFindingExitCode, stdout, stderr)
	}
	return stdout, stderr
}

func cliResult(t *testing.T, args ...string) (string, string, int) {
	t.Helper()
	cmd := exec.Command(os.Args[0], args...)
	cmd.Env = append(os.Environ(), "SECRETS_TEST_CLI=1", "GOMAXPROCS=2")
	var stdout, stderr strings.Builder
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	if err == nil {
		return stdout.String(), stderr.String(), 0
	}
	exitErr, ok := err.(*exec.ExitError)
	if !ok {
		t.Fatalf("secrets %v: %v\n%s%s", args, err, stdout.String(), stderr.String())
	}
	return stdout.String(), stderr.String(), exitErr.ExitCode()
}

// A synthetic GitHub personal access token: valid ghp_ prefix and 36-char
// base62 body so it matches the pattern without ever having been issued.
const fakeGitHubPAT = "ghp_" + "16C7e42F292c6912E7710c838347Ae178B4a"

type jsonFinding struct {
	Blob, Commit, Path, Rule, Secret string
	Line                             int
	Status                           string
	ValidationReason                 string         `json:"validation_reason"`
	ValidationMetadata               map[string]any `json:"validation_metadata"`
}

func parseJSONFindings(t *testing.T, output string) []jsonFinding {
	t.Helper()
	var findings []jsonFinding
	for line := range strings.SplitSeq(strings.TrimSpace(output), "\n") {
		if !strings.HasPrefix(line, "{") {
			continue
		}
		var finding jsonFinding
		if err := json.Unmarshal([]byte(line), &finding); err != nil {
			t.Fatalf("bad json line %q: %v", line, err)
		}
		findings = append(findings, finding)
	}
	return findings
}

func TestScanFindsHistoricalSecret(t *testing.T) {
	repo := repository(t)
	commitFile(t, repo, "config.yml", "token: "+fakeGitHubPAT+"\n", "add token")
	commitFile(t, repo, "config.yml", "token: ${TOKEN}\n", "remove token")
	git(t, repo, "gc")

	out := cliFindings(t, "scan", repo, "--format", "tsv")
	if !strings.Contains(out, "github") || !strings.Contains(out, "\tconfig.yml\t") {
		t.Fatalf("expected github hit attributed to config.yml:\n%s", out)
	}
	if !strings.Contains(out, " 1 findings in 1 blobs, 1 occurrences") {
		t.Fatalf("expected summary line:\n%s", out)
	}
	if strings.Contains(out, fakeGitHubPAT) {
		t.Fatalf("secret must be redacted by default:\n%s", out)
	}
}

func TestScanSharedCloneWithoutGit(t *testing.T) {
	repo := repository(t)
	commitFile(t, repo, "config.yml", "token: "+fakeGitHubPAT+"\n", "add token")
	commitFile(t, repo, "config.yml", "token: ${TOKEN}\n", "remove token")
	git(t, repo, "gc", "--quiet")
	shared := filepath.Join(t.TempDir(), "shared")
	git(t, repo, "clone", "--shared", repo, shared)

	cmd := exec.Command(os.Args[0], "scan", shared, "--format", "json", "--redact=false")
	cmd.Env = append(os.Environ(), "SECRETS_TEST_CLI=1", "GOMAXPROCS=2", "PATH="+t.TempDir())
	var stdout, stderr strings.Builder
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	exitErr, ok := err.(*exec.ExitError)
	if !ok || exitErr.ExitCode() != defaultFindingExitCode {
		t.Fatalf("shared scan: %v\n%s%s", err, stdout.String(), stderr.String())
	}
	findings := parseJSONFindings(t, stdout.String())
	if len(findings) != 1 || findings[0].Secret != fakeGitHubPAT || findings[0].Path != "config.yml" {
		t.Fatalf("shared findings=%+v\n%s", findings, stderr.String())
	}
	if !strings.Contains(stderr.String(), "1 findings in 1 blobs, 1 occurrences") {
		t.Fatalf("shared scan summary:\n%s", stderr.String())
	}
}

func TestScanNoAttribute(t *testing.T) {
	repo := repository(t)
	commitFile(t, repo, "config.yml", "token: "+fakeGitHubPAT+"\n", "add token")
	out := cliFindings(t, "scan", repo, "--attribute=false")
	if strings.Contains(out, "config.yml") {
		t.Fatalf("--attribute=false must not resolve paths:\n%s", out)
	}
	if !strings.Contains(out, "github") {
		t.Fatalf("expected github hit:\n%s", out)
	}
}

func TestScanSarif(t *testing.T) {
	repo := repository(t)
	commitFile(t, repo, "config.yml", "token: "+fakeGitHubPAT+"\n", "add token")
	body, _ := cliSplitFindings(t, "scan", repo, "--format", "sarif")
	var doc struct {
		Version string
		Runs    []struct {
			Results []struct {
				RuleID    string
				Locations []struct {
					PhysicalLocation struct {
						ArtifactLocation struct{ URI string }
					}
				}
			}
		}
	}
	if err := json.Unmarshal([]byte(body), &doc); err != nil {
		t.Fatalf("sarif output not valid json: %v\n%s", err, body)
	}
	if doc.Version != "2.1.0" || len(doc.Runs) != 1 || len(doc.Runs[0].Results) == 0 {
		t.Fatalf("bad sarif structure:\n%s", body)
	}
	r := doc.Runs[0].Results[0]
	if !strings.Contains(r.RuleID, "github") {
		t.Fatalf("wrong rule id %q", r.RuleID)
	}
	if r.Locations[0].PhysicalLocation.ArtifactLocation.URI != "config.yml" {
		t.Fatalf("wrong location %+v", r.Locations)
	}
	log, err := sarif.Parse([]byte(body))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := sarif.Validate(log); err != nil {
		t.Fatalf("schema validation: %v\n%s", err, body)
	}
}

func TestScanJSON(t *testing.T) {
	repo := repository(t)
	commitFile(t, repo, "app.env", "GITHUB_TOKEN="+fakeGitHubPAT+"\n", "leak")

	out := cliFindings(t, "scan", repo, "--format", "json", "--redact=false")
	var found bool
	for line := range strings.SplitSeq(strings.TrimSpace(out), "\n") {
		if !strings.HasPrefix(line, "{") {
			continue
		}
		var v struct {
			Blob, Commit, Path, Rule, Secret string
			Line                             int
		}
		if err := json.Unmarshal([]byte(line), &v); err != nil {
			t.Fatalf("bad json line %q: %v", line, err)
		}
		if v.Secret == fakeGitHubPAT && v.Line == 1 && v.Blob != "" && v.Commit != "" && v.Path == "app.env" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected unredacted json finding:\n%s", out)
	}
}

func TestScanAppliesPathRulePerOccurrence(t *testing.T) {
	repo := repository(t)
	content := `"secret_key" => "sk_` + strings.Repeat("A7", 14) + `A"` + "\n"
	commitFile(t, repo, "config.php", content, "add PHP secret")
	commitFile(t, repo, "config.txt", content, "reuse content")

	out := cliFindings(t, "scan", repo, "--format", "json", "--redact=false")
	var paths []string
	for _, finding := range parseJSONFindings(t, out) {
		if finding.Rule == "freemius-secret-key" {
			paths = append(paths, finding.Path)
		}
	}
	if len(paths) != 1 || paths[0] != "config.php" {
		t.Fatalf("expected Freemius finding only at config.php, got %v:\n%s", paths, out)
	}
}

func TestScanDetectsPathOnlyRule(t *testing.T) {
	repo := repository(t)
	commitFile(t, repo, "certs/client.p12", "\x00PKCS12 fixture\n", "add certificate")

	out := cliFindings(t, "scan", repo, "--format", "json")
	for _, finding := range parseJSONFindings(t, out) {
		if finding.Rule == "pkcs12-file" && finding.Path == "certs/client.p12" {
			return
		}
	}
	t.Fatalf("expected PKCS #12 path finding:\n%s", out)
}

func TestValidatedScanDetectsPathOnlyRule(t *testing.T) {
	repo := repository(t)
	commitFile(t, repo, "certs/client.p12", "\x00PKCS12 fixture\n", "add certificate")

	out := cliFindings(t, "scan", repo, "--validate", "--format", "json")
	for _, finding := range parseJSONFindings(t, out) {
		if finding.Rule == "pkcs12-file" && finding.Path == "certs/client.p12" {
			return
		}
	}
	t.Fatalf("expected validated PKCS #12 path finding:\n%s", out)
}

func TestScanValidationUsesCacheAndReportsDetails(t *testing.T) {
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Oauth-Scopes", "repo")
		_ = json.NewEncoder(w).Encode(map[string]string{"login": "octocat", "name": fakeGitHubPAT})
	}))
	defer server.Close()
	t.Setenv("GITHUB_BASE_URL", server.URL)

	repo := repository(t)
	commitFile(t, repo, "first.yml", "token: "+fakeGitHubPAT+"\n", "add first token")
	commitFile(t, repo, "second.yml", "github_token = "+fakeGitHubPAT+"\n", "reuse token")

	out := cliFindings(t, "scan", repo, "--validate", "--validation-env-vars", "GITHUB_BASE_URL", "--format", "json")
	var findings int
	for _, finding := range parseJSONFindings(t, out) {
		if finding.Rule != "github-pat" {
			continue
		}
		findings++
		if finding.Status != "valid" || finding.ValidationMetadata["username"] != "octocat" ||
			finding.ValidationMetadata["name"] != "[redacted]" {
			t.Fatalf("unexpected validation result: %+v\n%s", finding, out)
		}
	}
	if findings != 2 || requests.Load() != 1 {
		t.Fatalf("findings = %d, requests = %d, want 2 findings and 1 request\n%s", findings, requests.Load(), out)
	}

	tsv := cliFindings(t, "scan", repo, "--validate", "--validation-env-vars", "GITHUB_BASE_URL", "--format", "tsv")
	if !strings.Contains(tsv, "status\treason\tmetadata") || !strings.Contains(tsv, `"username":"octocat"`) || strings.Contains(tsv, fakeGitHubPAT) {
		t.Fatalf("TSV validation details missing or unredacted:\n%s", tsv)
	}

	body, _ := cliSplitFindings(t, "scan", repo, "--validate", "--validation-env-vars", "GITHUB_BASE_URL", "--format", "sarif")
	var sarifDoc struct {
		Runs []struct {
			Results []struct {
				RuleID     string
				Properties map[string]any
			}
		}
	}
	if err := json.Unmarshal([]byte(body), &sarifDoc); err != nil {
		t.Fatalf("bad validation SARIF: %v\n%s", err, body)
	}
	if len(sarifDoc.Runs) != 1 {
		t.Fatalf("validation SARIF has %d runs, want 1\n%s", len(sarifDoc.Runs), body)
	}
	var sarifDetails bool
	for _, result := range sarifDoc.Runs[0].Results {
		metadata, _ := result.Properties["validation_metadata"].(map[string]any)
		if result.RuleID == "github-pat" && result.Properties["validation_status"] == "valid" && metadata["username"] == "octocat" {
			sarifDetails = true
		}
	}
	if !sarifDetails || strings.Contains(body, fakeGitHubPAT) {
		t.Fatalf("SARIF validation details missing or unredacted:\n%s", body)
	}
}

func TestScanValidationRequestLimit(t *testing.T) {
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"login":"octocat"}`)
	}))
	defer server.Close()
	t.Setenv("GITHUB_BASE_URL", server.URL)

	repo := repository(t)
	secondToken := fakeGitHubPAT[:len(fakeGitHubPAT)-1] + "Z"
	commitFile(t, repo, "first.yml", "token: "+fakeGitHubPAT+"\n", "add first token")
	commitFile(t, repo, "second.yml", "token: "+secondToken+"\n", "add second token")

	out := cliFindings(t, "scan", repo, "--validate", "--validation-env-vars", "GITHUB_BASE_URL",
		"--validation-max-requests-per-target", "1", "--validation-requests-per-second", "0", "--format", "json")
	var valid, limited int
	for _, finding := range parseJSONFindings(t, out) {
		if finding.Rule != "github-pat" {
			continue
		}
		switch finding.Status {
		case "valid":
			valid++
		case "needs_validation":
			limited++
			if finding.ValidationMetadata["betterleaks_validation_max_requests"] != float64(1) ||
				!strings.Contains(finding.ValidationReason, "request limit") {
				t.Fatalf("missing request-limit details: %+v", finding)
			}
		}
	}
	if valid != 1 || limited != 1 || requests.Load() != 1 {
		t.Fatalf("valid = %d, limited = %d, requests = %d\n%s", valid, limited, requests.Load(), out)
	}
}

func TestScanValidationRateLimit(t *testing.T) {
	requestTimes := make(chan time.Time, 2)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requestTimes <- time.Now()
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"login":"octocat"}`)
	}))
	defer server.Close()
	t.Setenv("GITHUB_BASE_URL", server.URL)

	repo := repository(t)
	secondToken := fakeGitHubPAT[:len(fakeGitHubPAT)-1] + "Z"
	commitFile(t, repo, "first.yml", "token: "+fakeGitHubPAT+"\n", "add first token")
	commitFile(t, repo, "second.yml", "token: "+secondToken+"\n", "add second token")
	cliFindings(t, "scan", repo, "--validate", "--validation-env-vars", "GITHUB_BASE_URL",
		"--validation-max-requests-per-target", "10", "--validation-requests-per-second", "20", "--format", "json")

	times := make([]time.Time, 0, 2)
	for len(times) < 2 {
		select {
		case requestTime := <-requestTimes:
			times = append(times, requestTime)
		case <-time.After(2 * time.Second):
			t.Fatalf("received %d validation requests, want 2", len(times))
		}
	}
	first, second := times[0], times[1]
	if second.Before(first) {
		first, second = second, first
	}
	if spacing := second.Sub(first); spacing < 35*time.Millisecond {
		t.Fatalf("validation requests spaced by %s, want at least 35ms", spacing)
	}
}

func TestScanValidationTimeout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer server.Close()
	t.Setenv("GITHUB_BASE_URL", server.URL)

	repo := repository(t)
	commitFile(t, repo, "config.yml", "token: "+fakeGitHubPAT+"\n", "add token")
	out := cliFindings(t, "scan", repo, "--validate", "--validation-env-vars", "GITHUB_BASE_URL",
		"--validate-timeout", "50ms", "--format", "json")
	for _, finding := range parseJSONFindings(t, out) {
		if finding.Rule == "github-pat" && finding.Status == "error" &&
			strings.Contains(strings.ToLower(finding.ValidationReason), "deadline") {
			return
		}
	}
	t.Fatalf("expected timeout validation error:\n%s", out)
}

func TestScanValidationInterrupt(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("interrupt signaling differs on Windows")
	}
	started := make(chan struct{}, 1)
	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		started <- struct{}{}
		<-r.Context().Done()
	}))
	defer server.Close()
	t.Setenv("GITHUB_BASE_URL", server.URL)

	repo := repository(t)
	commitFile(t, repo, "config.yml", "token: "+fakeGitHubPAT+"\n", "add token")
	cmd := exec.Command(os.Args[0], "scan", repo, "--validate", "--validation-env-vars", "GITHUB_BASE_URL", "--format", "json")
	cmd.Env = append(os.Environ(), "SECRETS_TEST_CLI=1", "GOMAXPROCS=2")
	var stdout, stderr strings.Builder
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatal("validation request did not start")
	}
	if err := cmd.Process.Signal(os.Interrupt); err != nil {
		t.Fatal(err)
	}
	wait := make(chan error, 1)
	go func() { wait <- cmd.Wait() }()
	select {
	case err := <-wait:
		exitErr, ok := err.(*exec.ExitError)
		if !ok || exitErr.ExitCode() != 1 || !strings.Contains(stderr.String(), "context canceled") {
			t.Fatalf("interrupt result: %v\n%s%s", err, stdout.String(), stderr.String())
		}
	case <-time.After(5 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatal("scan did not stop after interrupt")
	}
}

func TestScanAppliesPathPrefilterPerOccurrence(t *testing.T) {
	repo := repository(t)
	content := "token: " + fakeGitHubPAT + "\n"
	commitFile(t, repo, "go.mod", content, "add ignored module file")
	commitFile(t, repo, "config.yml", content, "reuse content")

	out := cliFindings(t, "scan", repo, "--format", "json")
	var foundConfig bool
	for _, finding := range parseJSONFindings(t, out) {
		if finding.Path == "go.mod" {
			t.Fatalf("path prefilter did not exclude go.mod:\n%s", out)
		}
		if finding.Path == "config.yml" {
			foundConfig = true
		}
	}
	if !foundConfig {
		t.Fatalf("expected finding at config.yml:\n%s", out)
	}
}

func TestScanFindsMultipleGenericSecrets(t *testing.T) {
	repo := repository(t)
	first := "Z7mQ2vN9xK4pR8sT6wY3cF5hJ1dL0bGa"
	second := "H4nC8qW1zM6rT9vB2kP7xD5sJ0fL3aYe"
	content := "api_key = \"" + first + "\"\n" + strings.Repeat("ordinary text\n", 100) + "auth_token = \"" + second + "\"\n"
	commitFile(t, repo, "config.txt", content, "add tokens")
	out, _ := cliSplitFindings(t, "scan", repo, "--attribute=false", "--format", "json", "--redact=false")
	if got := strings.Count(out, `"rule":"generic-api-key"`); got != 2 {
		t.Fatalf("expected 2 generic API key findings, got %d:\n%s", got, out)
	}
}

func TestScanCleanRepo(t *testing.T) {
	repo := repository(t)
	commitFile(t, repo, "README.md", "nothing here\n", "init")
	out := cli(t, "scan", repo)
	if !strings.Contains(out, "0 findings") {
		t.Fatalf("expected 0 findings:\n%s", out)
	}
}

func TestScanExitCodes(t *testing.T) {
	cleanRepo := repository(t)
	commitFile(t, cleanRepo, "README.md", "nothing here\n", "init")
	_, _, code := cliResult(t, "scan", cleanRepo, "--format", "json")
	if code != 0 {
		t.Fatalf("clean scan exit = %d, want 0", code)
	}

	leakyRepo := repository(t)
	commitFile(t, leakyRepo, "config.yml", "token: "+fakeGitHubPAT+"\n", "add token")
	_, _, code = cliResult(t, "scan", leakyRepo, "--format", "json")
	if code != defaultFindingExitCode {
		t.Fatalf("finding scan exit = %d, want %d", code, defaultFindingExitCode)
	}
	_, _, code = cliResult(t, "scan", leakyRepo, "--format", "json", "--exit-code", "7")
	if code != 7 {
		t.Fatalf("custom finding exit = %d, want 7", code)
	}
	_, _, code = cliResult(t, "scan", leakyRepo, "--format", "json", "--exit-code", "0")
	if code != 0 {
		t.Fatalf("disabled finding exit = %d, want 0", code)
	}

	_, stderr, code := cliResult(t, "scan", filepath.Join(t.TempDir(), "missing"))
	if code != 1 || !strings.Contains(stderr, "secrets:") {
		t.Fatalf("operational failure exit = %d, stderr = %q", code, stderr)
	}
	_, stderr, code = cliResult(t, "scan", cleanRepo, "--exit-code", "256")
	if code != 1 || !strings.Contains(stderr, "--exit-code must be between 0 and 255") {
		t.Fatalf("invalid exit code result = %d, stderr = %q", code, stderr)
	}
	_, stderr, code = cliResult(t, "scan", cleanRepo, "--validation-workers", "0")
	if code != 1 || !strings.Contains(stderr, "--validation-workers must be greater than zero") {
		t.Fatalf("invalid validation workers result = %d, stderr = %q", code, stderr)
	}
}

func TestScanBrokenOutputIsOperationalFailure(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("broken pipe signaling differs on Windows")
	}
	repo := repository(t)
	commitFile(t, repo, "README.md", "nothing here\n", "init")
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(os.Args[0], "scan", repo, "--exit-code", "7")
	cmd.Env = append(os.Environ(), "SECRETS_TEST_CLI=1", "GOMAXPROCS=2")
	cmd.Stdout = writer
	var stderr strings.Builder
	cmd.Stderr = &stderr
	err = cmd.Run()
	_ = writer.Close()
	exitErr, ok := err.(*exec.ExitError)
	if !ok || exitErr.ExitCode() == 0 || exitErr.ExitCode() == 7 {
		t.Fatalf("broken output result: %v, stderr = %q", err, stderr.String())
	}
}

func TestScanSkipsBinary(t *testing.T) {
	repo := repository(t)
	commitFile(t, repo, "blob.bin", "\x00\x01\x02"+fakeGitHubPAT, "binary")
	out := cli(t, "scan", repo)
	if !strings.Contains(out, "0 findings") || !strings.Contains(out, "1 skipped") {
		t.Fatalf("binary blob should be skipped:\n%s", out)
	}
}

func TestScanSkipsBinaryWithLateNUL(t *testing.T) {
	repo := repository(t)
	content := strings.Repeat("a", 9000) + "\x00token: " + fakeGitHubPAT + "\n"
	commitFile(t, repo, "late-nul.bin", content, "binary with late NUL")
	out := cli(t, "scan", repo)
	if !strings.Contains(out, "0 findings") || !strings.Contains(out, "1 skipped") {
		t.Fatalf("binary blob with late NUL should be skipped:\n%s", out)
	}
}

func TestScanSkipsKnownBinaryFormat(t *testing.T) {
	repo := repository(t)
	commitFile(t, repo, "document.pdf", "%PDF-1.7\ntoken: "+fakeGitHubPAT+"\n", "add PDF")
	out := cli(t, "scan", repo, "--format", "json")
	if !strings.Contains(out, "0 findings") || !strings.Contains(out, "1 skipped") {
		t.Fatalf("PDF blob should be skipped:\n%s", out)
	}
}

func TestScanFindsUTF16Secrets(t *testing.T) {
	repo := repository(t)
	content := "token: " + fakeGitHubPAT + "\n"
	commitFile(t, repo, "little-endian.env", encodedUTF16(content, binary.LittleEndian), "add little-endian token")
	commitFile(t, repo, "big-endian.env", encodedUTF16(content, binary.BigEndian), "add big-endian token")

	out := cliFindings(t, "scan", repo, "--format", "json", "--redact=false")
	paths := make(map[string]bool)
	for _, finding := range parseJSONFindings(t, out) {
		if finding.Rule == "github-pat" && finding.Secret == fakeGitHubPAT {
			paths[finding.Path] = true
		}
	}
	if !paths["little-endian.env"] || !paths["big-endian.env"] {
		t.Fatalf("expected UTF-16 findings at both paths, got %v:\n%s", paths, out)
	}
}

func TestScanPreservesUnknownEncoding(t *testing.T) {
	repo := repository(t)
	content := string([]byte{0xff}) + "token: " + fakeGitHubPAT + "\n"
	commitFile(t, repo, "unknown.env", content, "add token with invalid UTF-8 prefix")

	out := cliFindings(t, "scan", repo, "--format", "json", "--redact=false")
	for _, finding := range parseJSONFindings(t, out) {
		if finding.Rule == "github-pat" && finding.Secret == fakeGitHubPAT && finding.Path == "unknown.env" {
			return
		}
	}
	t.Fatalf("expected finding in unknown encoding:\n%s", out)
}

func TestScanWritesProfiles(t *testing.T) {
	repo := repository(t)
	commitFile(t, repo, "config.yml", "token: "+fakeGitHubPAT+"\n", "add token")
	cpu := filepath.Join(t.TempDir(), "cpu.pprof")
	heap := filepath.Join(t.TempDir(), "heap.pprof")
	timings := filepath.Join(t.TempDir(), "rules.csv")
	cliFindings(t, "scan", repo, "--attribute=false", "--cpuprofile", cpu, "--memprofile", heap, "--rule-timings", timings)
	for _, path := range []string{cpu, heap, timings} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Size() == 0 {
			t.Fatalf("empty profile %s", path)
		}
	}
}

func TestRules(t *testing.T) {
	out := cli(t, "rules")
	if !strings.Contains(out, "github") {
		t.Fatalf("expected github rule listed:\n%s", out)
	}
	lines := strings.Count(out, "\n")
	if lines < 100 {
		t.Fatalf("expected >100 rules, got %d lines:\n%s", lines, out)
	}
}

func TestPrepareBlob(t *testing.T) {
	plain := []byte("plain text")
	prepared, binaryContent := prepareBlob(plain)
	if binaryContent || string(prepared) != string(plain) {
		t.Fatalf("plain text prepared as %q, binary = %v", prepared, binaryContent)
	}

	content := "token: " + fakeGitHubPAT + "\n"
	for _, order := range []binary.ByteOrder{binary.LittleEndian, binary.BigEndian} {
		prepared, binaryContent = prepareBlob([]byte(encodedUTF16(content, order)))
		if binaryContent || string(prepared) != content {
			t.Fatalf("UTF-16 prepared as %q, binary = %v", prepared, binaryContent)
		}
	}

	unknown := []byte{0xff, 't', 'e', 'x', 't'}
	prepared, binaryContent = prepareBlob(unknown)
	if binaryContent || string(prepared) != string(unknown) {
		t.Fatalf("unknown encoding prepared as %q, binary = %v", prepared, binaryContent)
	}

	prepared, binaryContent = prepareBlob([]byte("has\x00null"))
	if !binaryContent || prepared != nil {
		t.Fatalf("binary prepared as %q, binary = %v", prepared, binaryContent)
	}
}
