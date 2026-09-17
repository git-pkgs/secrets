package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const (
	upstreamModule = "github.com/betterleaks/betterleaks"
	corpusFileMode = 0o644
)

type corpusSource struct {
	Module  string `json:"module"`
	Version string `json:"version"`
	Sum     string `json:"sum"`
	Dir     string `json:"-"`
}

type moduleDownload struct {
	Path    string
	Version string
	Sum     string
	Dir     string
}

func main() {
	version := flag.String("version", "latest", "Betterleaks module version")
	sourceDir := flag.String("source", "", "local Betterleaks checkout instead of a module download")
	root := flag.String("root", ".", "secrets repository root")
	flag.Parse()

	source := corpusSource{Module: upstreamModule, Version: *version, Dir: *sourceDir}
	if source.Dir == "" {
		downloaded, err := downloadCorpus(context.Background(), *version)
		if err != nil {
			fail(err)
		}
		source = downloaded
	}
	if err := syncCorpus(*root, source); err != nil {
		fail(err)
	}
	fmt.Fprintf(os.Stderr, "synccorpus: loaded %s %s; run go generate -tags gohs .\n", source.Module, source.Version)
}

func downloadCorpus(ctx context.Context, version string) (corpusSource, error) {
	cmd := exec.CommandContext(ctx, "go", "mod", "download", "-json", upstreamModule+"@"+version)
	out, err := cmd.Output()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return corpusSource{}, fmt.Errorf("download %s: %s", version, strings.TrimSpace(string(exitErr.Stderr)))
		}
		return corpusSource{}, err
	}
	return parseModuleDownload(out)
}

func parseModuleDownload(data []byte) (corpusSource, error) {
	var downloaded moduleDownload
	if err := json.Unmarshal(data, &downloaded); err != nil {
		return corpusSource{}, fmt.Errorf("parse module download: %w", err)
	}
	if downloaded.Path == "" || downloaded.Dir == "" || downloaded.Version == "" {
		return corpusSource{}, fmt.Errorf("module download returned incomplete metadata")
	}
	return corpusSource{
		Module: downloaded.Path, Version: downloaded.Version,
		Sum: downloaded.Sum, Dir: downloaded.Dir,
	}, nil
}

func syncCorpus(root string, source corpusSource) error {
	corpus, err := os.ReadFile(filepath.Join(source.Dir, "config", "betterleaks.toml"))
	if err != nil {
		return err
	}
	if !strings.Contains(string(corpus), "[[rules]]") {
		return fmt.Errorf("source corpus contains no rules")
	}
	metadata, err := json.MarshalIndent(corpusSource{
		Module: source.Module, Version: source.Version, Sum: source.Sum,
	}, "", "  ")
	if err != nil {
		return err
	}
	metadata = append(metadata, '\n')
	if err := writeAtomic(filepath.Join(root, "betterleaks", "config", "betterleaks.toml"), corpus); err != nil {
		return err
	}
	return writeAtomic(filepath.Join(root, "betterleaks", "corpus.json"), metadata)
}

func writeAtomic(path string, data []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".synccorpus-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer func() { _ = os.Remove(tmp) }()
	if err := f.Chmod(corpusFileMode); err != nil {
		_ = f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "synccorpus:", err)
	os.Exit(1)
}
