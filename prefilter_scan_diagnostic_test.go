//go:build scan && !gohs

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/betterleaks/betterleaks/config"
	"github.com/git-pkgs/history"
	"github.com/git-pkgs/scan"
)

func TestScanBlobTimings(t *testing.T) {
	repoPath := os.Getenv("SCAN_DIAGNOSTIC_REPO")
	if repoPath == "" {
		t.Skip("set SCAN_DIAGNOSTIC_REPO")
	}
	configureRegexpEngine()
	cfg, err := config.Default()
	if err != nil {
		t.Fatal(err)
	}
	pf, err := newPrefilter(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if pf.engine() != "scan-embedded" {
		t.Fatalf("unexpected engine: %s", pf.engine())
	}
	repo, err := history.Open(repoPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = repo.Close() }()
	scratch := scan.NewScratch(pf.db)
	type timing struct {
		oid      string
		data     []byte
		duration time.Duration
	}
	var slowest []timing
	var totalTime time.Duration
	total, err := repo.WalkBlobs(history.BlobOptions{
		Workers: 1,
		Limit:   func(string) int64 { return defaultMaxBlobSize },
	}, func(blob history.Blob) error {
		data, _ := prepareBlob(blob.Data)
		handler := func(scan.Match) error { return nil }
		if err := pf.db.Scan(data, scratch, handler); err != nil {
			return err
		}
		started := time.Now()
		if err := pf.db.Scan(data, scratch, handler); err != nil {
			return err
		}
		duration := time.Since(started)
		totalTime += duration
		if len(slowest) == 10 && duration <= slowest[len(slowest)-1].duration {
			return nil
		}
		slowest = append(slowest, timing{oid: blob.OID, data: bytes.Clone(data), duration: duration})
		sort.Slice(slowest, func(i, j int) bool { return slowest[i].duration > slowest[j].duration })
		if len(slowest) > 10 {
			slowest = slowest[:10]
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	directory := os.Getenv("SCAN_DIAGNOSTIC_DIR")
	if directory != "" {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	t.Logf("engine=%s blobs=%d measured scan time=%s", pf.engine(), total, totalTime)
	for _, result := range slowest {
		t.Logf("blob=%s bytes=%d scan=%s", result.oid, len(result.data), result.duration)
		if directory != "" {
			if err := os.WriteFile(filepath.Join(directory, result.oid), result.data, 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
}
