package main

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/git-pkgs/secrets/betterleaks/config"
	"github.com/git-pkgs/secrets/betterleaks/detect"
	"github.com/git-pkgs/secrets/scanner"
)

func scanDirCmd(ctx context.Context, dir string) error {
	if err := validateScanOptions(); err != nil {
		return err
	}
	if info, err := os.Stat(dir); err != nil {
		return err
	} else if !info.IsDir() {
		return fmt.Errorf("--dir %s: not a directory", dir)
	}
	cfg, err := config.Default()
	if err != nil {
		return err
	}
	var timings *detect.RuleTimingCollector
	if ruleTimings != "" {
		timings = detect.NewRuleTimingCollector()
	}
	sc, err := newScanner(ctx, timings)
	if err != nil {
		return err
	}
	defer func() { _ = sc.Close() }()
	emit, done, err := newEmitter(os.Stdout, format, cfg, redact)
	if err != nil {
		return err
	}

	var stats scanStats
	hits := make(detectionHits)
	start := time.Now()
	stopCPUProfile, err := startCPUProfile(cpuProfile)
	if err != nil {
		return err
	}
	err = sc.ScanFS(ctx, os.DirFS(dir), scanner.FSOptions{
		Workers:     workers,
		MaxFileSize: maxBlobSize,
		Skipped:     func(string) { stats.total++; stats.skipped++ },
	}, func(f scanner.File) error {
		stats.total++
		if f.Result.Scanned {
			stats.scanned++
		} else {
			stats.skipped++
		}
		if len(f.Result.Findings) > 0 {
			hits[blobPath{blob: blobOID(f.Data), path: f.Path}] = f.Result.Findings
		}
		return nil
	})
	profileErr := stopCPUProfile()
	if err != nil {
		return err
	}
	if profileErr != nil {
		return profileErr
	}
	stats.blobPhase = time.Since(start)
	if err := writeHeapProfile(memProfile); err != nil {
		return err
	}
	if err := writeRuleTimings(ruleTimings, timings); err != nil {
		return err
	}
	stats.hitBlobs, stats.findings = hitStats(hits)

	keys := make([]blobPath, 0, len(hits))
	for key := range hits {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i].path < keys[j].path })
	for _, key := range keys {
		stats.occurrences++
		for _, r := range hits[key] {
			if err := emit(Finding{Blob: key.blob, Path: key.path, Report: r}); err != nil {
				return err
			}
		}
	}
	if err := done(); err != nil {
		return err
	}
	printStats(&stats, sc.Engine())
	if stats.findings > 0 && findingExitCode != 0 {
		return findingExitError{code: findingExitCode}
	}
	return nil
}

// blobOID is the Git SHA-1 blob ID of data, so a finding names the same blob as a repository scan.
func blobOID(data []byte) string {
	h := sha1.New()
	_, _ = fmt.Fprintf(h, "blob %d\x00", len(data))
	_, _ = h.Write(data)
	return hex.EncodeToString(h.Sum(nil))
}
