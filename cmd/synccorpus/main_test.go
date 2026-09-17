package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestDownloadCorpus(t *testing.T) {
	source, err := parseModuleDownload([]byte(`{
		"Path": "github.com/betterleaks/betterleaks",
		"Version": "v1.8.1",
		"Sum": "h1:test",
		"Dir": "/module/cache/betterleaks@v1.8.1"
	}`))
	if err != nil {
		t.Fatal(err)
	}
	if source.Module != upstreamModule || source.Version != "v1.8.1" || source.Dir != "/module/cache/betterleaks@v1.8.1" || source.Sum != "h1:test" {
		t.Fatalf("source = %+v", source)
	}
}

func TestSyncCorpus(t *testing.T) {
	source := t.TempDir()
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(source, "config"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "betterleaks", "config"), 0o755); err != nil {
		t.Fatal(err)
	}
	wantCorpus := []byte("[[rules]]\nid = \"example\"\n")
	if err := os.WriteFile(filepath.Join(source, "config", "betterleaks.toml"), wantCorpus, 0o644); err != nil {
		t.Fatal(err)
	}
	wantSource := corpusSource{Module: upstreamModule, Version: "v9.8.7", Sum: "h1:test", Dir: source}
	if err := syncCorpus(root, wantSource); err != nil {
		t.Fatal(err)
	}
	gotCorpus, err := os.ReadFile(filepath.Join(root, "betterleaks", "config", "betterleaks.toml"))
	if err != nil {
		t.Fatal(err)
	}
	if string(gotCorpus) != string(wantCorpus) {
		t.Fatalf("corpus = %q, want %q", gotCorpus, wantCorpus)
	}
	metadata, err := os.ReadFile(filepath.Join(root, "betterleaks", "corpus.json"))
	if err != nil {
		t.Fatal(err)
	}
	var gotSource corpusSource
	if err := json.Unmarshal(metadata, &gotSource); err != nil {
		t.Fatal(err)
	}
	if gotSource.Module != wantSource.Module || gotSource.Version != wantSource.Version || gotSource.Sum != wantSource.Sum {
		t.Fatalf("metadata = %+v, want %+v", gotSource, wantSource)
	}
}
