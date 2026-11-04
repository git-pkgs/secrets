package scanner_test

import (
	"context"
	"encoding/binary"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unicode/utf16"

	"github.com/git-pkgs/secrets/betterleaks/config"
	"github.com/git-pkgs/secrets/betterleaks/detect"
	"github.com/git-pkgs/secrets/scanner"
)

const token = "ghp_" + "16C7e42F292c6912E7710c838347Ae178B4a"

func newScanner(t *testing.T, opts scanner.Options) *scanner.Scanner {
	t.Helper()
	s, err := scanner.New(context.Background(), opts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := s.Close(); err != nil {
			t.Error(err)
		}
	})
	return s
}

func TestScan(t *testing.T) {
	s := newScanner(t, scanner.Options{})
	for _, test := range []struct {
		name, content, path, rule, secret string
		line                              int
		scanned                           bool
	}{
		{"token", "# config\ntoken: " + token + "\n", "config.yml", "github-pat", token, 2, true},
		{"no path", "token: " + token + "\n", "", "github-pat", token, 1, true},
		{"path-only binary", "\x00PKCS12 fixture\n", "certs/client.p12", "pkcs12-file", "", 0, false},
		{"path-only empty", "", "certs/client.p12", "pkcs12-file", "", 0, true},
		{"clean", "ordinary text\n", "config.yml", "", "", 0, false},
		{"binary", "\x00token: " + token, "image.bin", "", "", 0, false},
		{"excluded path", "token: " + token, "go.sum", "", "", 0, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			result, err := s.Scan(context.Background(), []byte(test.content), test.path)
			if err != nil {
				t.Fatal(err)
			}
			if result.Scanned != test.scanned {
				t.Fatalf("scanned=%v, want %v", result.Scanned, test.scanned)
			}
			if test.rule == "" {
				if len(result.Findings) != 0 {
					t.Fatalf("unexpected findings: %+v", result.Findings)
				}
				return
			}
			if len(result.Findings) != 1 {
				t.Fatalf("findings=%+v", result.Findings)
			}
			finding := result.Findings[0]
			if finding.RuleID != test.rule || finding.Secret != test.secret || finding.StartLine != test.line || finding.File != test.path {
				t.Fatalf("finding=%+v", finding)
			}
		})
	}
}

func TestScanUTF16(t *testing.T) {
	s := newScanner(t, scanner.Options{})
	for _, order := range []binary.ByteOrder{binary.LittleEndian, binary.BigEndian} {
		units := utf16.Encode([]rune("# config\ntoken: " + token + "\n"))
		data := make([]byte, 2+len(units)*2)
		order.PutUint16(data, 0xfeff)
		for i, unit := range units {
			order.PutUint16(data[2+i*2:], unit)
		}
		result, err := s.Scan(context.Background(), data, "config.yml")
		if err != nil || len(result.Findings) != 1 || result.Findings[0].Secret != token || result.Findings[0].StartLine != 2 {
			t.Fatalf("result=%+v err=%v", result, err)
		}
	}
}

func TestScanConcurrent(t *testing.T) {
	s := newScanner(t, scanner.Options{})
	var wg sync.WaitGroup
	for i := range 16 {
		wg.Go(func() {
			path := "config.yml"
			data := []byte("token: " + token + "\n")
			want := "github-pat"
			if i%2 == 0 {
				path, data, want = "certs/client.p12", []byte("\x00binary"), "pkcs12-file"
			}
			result, err := s.Scan(context.Background(), data, path)
			if err != nil || len(result.Findings) != 1 || result.Findings[0].RuleID != want || result.Findings[0].File != path {
				t.Errorf("result=%+v err=%v", result, err)
			}
		})
	}
	wg.Wait()
}

func TestScanPathRestriction(t *testing.T) {
	s := newScanner(t, scanner.Options{})
	data := []byte(`"secret_key" => "sk_` + strings.Repeat("A7", 14) + `A"` + "\n")
	for _, path := range []string{"config.php", "config.txt", ""} {
		result, err := s.Scan(context.Background(), data, path)
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, finding := range result.Findings {
			found = found || finding.RuleID == "freemius-secret-key"
		}
		if found != (path == "config.php") {
			t.Fatalf("path=%q findings=%+v", path, result.Findings)
		}
	}
}

func TestScanCustomRules(t *testing.T) {
	cfg, err := config.ParseTOMLString(`[[rules]]
id = "custom-token"
description = "Fixture token"
regex = 'CUSTOM_[0-9]{8}'
keywords = ["CUSTOM_"]
`, "fixture.toml")
	if err != nil {
		t.Fatal(err)
	}
	s := newScanner(t, scanner.Options{Config: cfg})
	if !strings.HasSuffix(s.Engine(), "-compiled") {
		t.Fatalf("engine=%q", s.Engine())
	}
	result, err := s.Scan(context.Background(), []byte("CUSTOM_12345678"), "fixture.txt")
	if err != nil || len(result.Findings) != 1 || result.Findings[0].RuleID != "custom-token" {
		t.Fatalf("result=%+v err=%v", result, err)
	}
}

func TestScanValidationOptInAndCache(t *testing.T) {
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		_, _ = w.Write([]byte(`{"login":"octocat","id":1}`))
	}))
	defer server.Close()
	t.Setenv("GITHUB_BASE_URL", server.URL)
	local := newScanner(t, scanner.Options{Validation: detect.ValidationOptions{ValidationEnvVars: []string{"GITHUB_BASE_URL"}}})
	result, err := local.Scan(context.Background(), []byte(token), "config.yml")
	if err != nil || len(result.Findings) != 1 || result.Findings[0].ValidationStatus != "" || requests.Load() != 0 {
		t.Fatalf("local result=%+v err=%v requests=%d", result, err, requests.Load())
	}
	live := newScanner(t, scanner.Options{Validation: detect.ValidationOptions{
		Enabled: true, Workers: 2, Timeout: time.Second, ValidationEnvVars: []string{"GITHUB_BASE_URL"},
	}})
	for range 2 {
		result, err := live.Scan(context.Background(), []byte(token), "config.yml")
		if err != nil || len(result.Findings) != 1 || result.Findings[0].ValidationStatus != "valid" {
			t.Fatalf("validated result=%+v err=%v", result, err)
		}
	}
	if requests.Load() != 1 {
		t.Fatalf("requests=%d, want 1", requests.Load())
	}
}

func TestScanCancellationAndClose(t *testing.T) {
	s := newScanner(t, scanner.Options{})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.Scan(ctx, []byte(token), ""); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled scan err=%v", err)
	}
	if _, err := scanner.New(ctx, scanner.Options{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled construction err=%v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Scan(context.Background(), []byte(token), ""); err == nil {
		t.Fatal("scan after Close succeeded")
	}
}

func TestScanValidationConcurrent(t *testing.T) {
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		_, _ = w.Write([]byte(`{"login":"octocat","id":1}`))
	}))
	defer server.Close()
	t.Setenv("GITHUB_BASE_URL", server.URL)
	s := newScanner(t, scanner.Options{Validation: detect.ValidationOptions{
		Enabled: true, Workers: 2, Timeout: time.Second, ValidationEnvVars: []string{"GITHUB_BASE_URL"},
	}})
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			result, err := s.Scan(context.Background(), []byte(token), "config.yml")
			if err != nil || len(result.Findings) != 1 || result.Findings[0].ValidationStatus != "valid" {
				t.Errorf("result=%+v err=%v", result, err)
			}
		})
	}
	wg.Wait()
	if requests.Load() != 1 {
		t.Fatalf("requests=%d, want 1", requests.Load())
	}
}

func TestScanValidationCancellation(t *testing.T) {
	started := make(chan struct{})
	finished := make(chan struct{})
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if requests.Add(1) == 1 {
			close(started)
			<-r.Context().Done()
			close(finished)
			return
		}
		_, _ = w.Write([]byte(`{"login":"octocat","id":1}`))
	}))
	defer server.Close()
	t.Setenv("GITHUB_BASE_URL", server.URL)
	s := newScanner(t, scanner.Options{Validation: detect.ValidationOptions{
		Enabled: true, Workers: 1, Timeout: time.Second, ValidationEnvVars: []string{"GITHUB_BASE_URL"},
	}})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errorsCh := make(chan error, 1)
	go func() {
		_, err := s.Scan(ctx, []byte(token), "config.yml")
		errorsCh <- err
	}()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("validation did not start")
	}
	type scanResult struct {
		result scanner.Result
		err    error
	}
	concurrent := make(chan scanResult, 1)
	go func() {
		result, err := s.Scan(context.Background(), []byte(token), "other.yml")
		concurrent <- scanResult{result: result, err: err}
	}()
	cancel()
	if err := <-errorsCh; !errors.Is(err, context.Canceled) {
		t.Fatalf("scan err=%v", err)
	}
	select {
	case <-finished:
	case <-time.After(5 * time.Second):
		t.Fatal("validation request was not canceled")
	}
	other := <-concurrent
	if other.err != nil || len(other.result.Findings) != 1 || other.result.Findings[0].ValidationStatus != "valid" {
		t.Fatalf("concurrent scan after cancellation result=%+v err=%v", other.result, other.err)
	}
	result, err := s.Scan(context.Background(), []byte(token), "config.yml")
	if err != nil || len(result.Findings) != 1 || result.Findings[0].ValidationStatus != "valid" {
		t.Fatalf("scan after cancellation result=%+v err=%v", result, err)
	}
}

func TestScanCloseCancelsValidation(t *testing.T) {
	started := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		close(started)
		<-r.Context().Done()
	}))
	defer server.Close()
	t.Setenv("GITHUB_BASE_URL", server.URL)
	s := newScanner(t, scanner.Options{Validation: detect.ValidationOptions{
		Enabled: true, Workers: 1, Timeout: time.Second, ValidationEnvVars: []string{"GITHUB_BASE_URL"},
	}})
	errorsCh := make(chan error, 1)
	go func() {
		_, err := s.Scan(context.Background(), []byte(token), "config.yml")
		errorsCh <- err
	}()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("validation did not start")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-errorsCh; !errors.Is(err, context.Canceled) {
		t.Fatalf("scan err=%v", err)
	}
}
