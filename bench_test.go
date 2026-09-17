package main

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/betterleaks/betterleaks/config"
	"github.com/git-pkgs/history"
)

func benchmarkRepositories(b *testing.B) []string {
	b.Helper()
	value := os.Getenv("SECRETS_BENCH_REPOS")
	if value == "" {
		b.Skip("set SECRETS_BENCH_REPOS to a path-list of Git repositories")
	}
	var repos []string
	for _, repo := range filepath.SplitList(value) {
		if repo = strings.TrimSpace(repo); repo != "" {
			repos = append(repos, repo)
		}
	}
	if len(repos) == 0 {
		b.Skip("SECRETS_BENCH_REPOS contains no repository paths")
	}
	return repos
}

func BenchmarkDetectHistory(b *testing.B) {
	configureRegexpEngine()
	workers = runtime.GOMAXPROCS(0)
	maxBlobSize = defaultMaxBlobSize
	cfg, err := config.Default()
	if err != nil {
		b.Fatal(err)
	}
	detector := newDetector(context.Background(), cfg)
	prefilter, err := newPrefilter(cfg)
	if err != nil {
		b.Fatal(err)
	}
	for _, path := range benchmarkRepositories(b) {
		b.Run(filepath.Base(path), func(b *testing.B) {
			repo, err := history.Open(path)
			if err != nil {
				b.Fatal(err)
			}
			defer func() { _ = repo.Close() }()
			var stats scanStats
			for b.Loop() {
				stats = scanStats{}
				if _, err := detectBlobs(context.Background(), repo, detector, prefilter, nil, &stats); err != nil {
					b.Fatal(err)
				}
			}
			b.ReportMetric(float64(stats.total), "blobs/op")
			b.ReportMetric(float64(stats.scanned), "scanned/op")
			if stats.scanned > 0 {
				b.ReportMetric(float64(b.Elapsed().Nanoseconds())/(float64(b.N)*float64(stats.scanned))/1000, "us/scanned-blob")
			}
		})
	}
}
