package main

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"runtime/pprof"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/git-pkgs/history"
	"github.com/git-pkgs/secrets/betterleaks/config"
	"github.com/git-pkgs/secrets/betterleaks/detect"
	"github.com/git-pkgs/secrets/betterleaks/report"
	"github.com/git-pkgs/secrets/scanner"
	scannerre2 "github.com/git-pkgs/secrets/scanner/re2"
)

// Finding is one detected secret, optionally attributed to the commit and
// path where the containing blob was introduced.
type Finding struct {
	Blob   string
	Commit string
	Date   string
	Path   string
	Report report.Finding
}

type scanStats struct {
	total, scanned, skipped   int64
	hitBlobs, findings        int64
	occurrences               int64
	blobPhase, attributePhase time.Duration
}

type blobPath struct {
	blob string
	path string
}

type detectionHits map[blobPath][]report.Finding

func scanCmd(ctx context.Context, repo string) error {
	if err := validateScanOptions(); err != nil {
		return err
	}
	cfg, err := config.Default()
	if err != nil {
		return err
	}
	var timings *detect.RuleTimingCollector
	if ruleTimings != "" {
		timings = detect.NewRuleTimingCollector()
	}
	scannerre2.Enable()
	scanner, err := scanner.New(ctx, scanner.Options{
		Validation: detect.ValidationOptions{
			Enabled: validate, Workers: validationWorkers, Timeout: validateTimeout,
			MaxRequestsPerTarget: validationMaxRequestsPerTarget,
			RequestsPerSecond:    validationRequestsPerSecond,
			ValidationEnvVars:    validationEnvVars,
		},
		RuleTimings: timings,
	})
	if err != nil {
		return err
	}
	defer func() { _ = scanner.Close() }()
	r, err := history.Open(repo)
	if err != nil {
		return err
	}
	defer func() { _ = r.Close() }()

	emit, done, err := newEmitter(os.Stdout, format, cfg, redact)
	if err != nil {
		return err
	}

	var stats scanStats
	var paths map[string][]string
	if attribute {
		start := time.Now()
		paths, err = indexBlobPaths(r)
		stats.attributePhase = time.Since(start)
		if err != nil {
			return err
		}
	}

	start := time.Now()
	stopCPUProfile, err := startCPUProfile(cpuProfile)
	if err != nil {
		return err
	}
	hits, err := detectBlobs(ctx, r, scanner, paths, &stats)
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

	start = time.Now()
	if attribute {
		err = attributeFindings(r, hits, emit, &stats)
	} else {
		err = emitUnattributed(hits, emit, &stats)
	}
	if err != nil {
		return err
	}
	stats.attributePhase += time.Since(start)
	if err := done(); err != nil {
		return err
	}
	printStats(&stats, scanner.Engine())
	if stats.findings > 0 && findingExitCode != 0 {
		return findingExitError{code: findingExitCode}
	}
	return nil
}

func writeRuleTimings(path string, timings *detect.RuleTimingCollector) error {
	if path == "" {
		return nil
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	if err := detect.WriteRuleTimingsCSV(f, timings.Snapshot()); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

func startCPUProfile(path string) (func() error, error) {
	if path == "" {
		return func() error { return nil }, nil
	}
	f, err := os.Create(path)
	if err != nil {
		return nil, err
	}
	if err := pprof.StartCPUProfile(f); err != nil {
		_ = f.Close()
		return nil, err
	}
	return func() error {
		pprof.StopCPUProfile()
		return f.Close()
	}, nil
}

func writeHeapProfile(path string) error {
	if path == "" {
		return nil
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	runtime.GC()
	if err := pprof.WriteHeapProfile(f); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

func indexBlobPaths(r *history.Repo) (map[string][]string, error) {
	paths := make(map[string][]string)
	seen := make(map[string]map[string]struct{})
	err := r.WalkChanges(history.ChangeOptions{Workers: workers, Merges: true}, func(c history.Change) error {
		if c.Path == "" || c.NewOID == "" || strings.TrimLeft(c.NewOID, "0") == "" {
			return nil
		}
		if seen[c.NewOID] == nil {
			seen[c.NewOID] = make(map[string]struct{})
		}
		if _, ok := seen[c.NewOID][c.Path]; ok {
			return nil
		}
		seen[c.NewOID][c.Path] = struct{}{}
		paths[c.NewOID] = append(paths[c.NewOID], c.Path)
		return nil
	})
	return paths, err
}

func detectBlobs(ctx context.Context, r *history.Repo, scanner *scanner.Scanner, paths map[string][]string, stats *scanStats) (detectionHits, error) {
	hits := make(detectionHits)
	var mu sync.Mutex
	var scanned, skipped atomic.Int64
	total, err := r.WalkBlobs(history.BlobOptions{
		Workers: workers,
		Limit:   func(string) int64 { return maxBlobSize },
		Skip:    func(string) { skipped.Add(1) },
	}, func(b history.Blob) error {
		if err := ctx.Err(); err != nil {
			return err
		}

		blobPaths := paths[b.OID]
		if paths == nil {
			blobPaths = []string{""}
		}
		matched := false
		for _, path := range blobPaths {
			result, err := scanner.Scan(ctx, b.Data, path)
			if err != nil {
				return err
			}
			findings, candidate := result.Findings, result.Scanned
			if len(findings) > 0 {
				mu.Lock()
				hits[blobPath{blob: b.OID, path: path}] = findings
				mu.Unlock()
			}
			if !candidate {
				continue
			}
			matched = true
		}
		if !matched {
			skipped.Add(1)
			return nil
		}
		scanned.Add(1)
		return nil
	})
	stats.total, stats.scanned, stats.skipped = int64(total), scanned.Load(), skipped.Load()
	return hits, err
}

func attributeFindings(r *history.Repo, hits detectionHits, emit emitFunc, stats *scanStats) error {
	if len(hits) == 0 {
		return nil
	}
	return r.WalkChanges(history.ChangeOptions{Workers: workers, Merges: true}, func(c history.Change) error {
		findings, ok := hits[blobPath{blob: c.NewOID, path: c.Path}]
		if !ok {
			return nil
		}
		stats.occurrences++
		for i := range findings {
			if err := emit(Finding{
				Blob: c.NewOID, Commit: c.Commit, Date: c.Date, Path: c.Path,
				Report: findings[i],
			}); err != nil {
				return err
			}
		}
		return nil
	})
}

func emitUnattributed(hits detectionHits, emit emitFunc, stats *scanStats) error {
	for key, findings := range hits {
		stats.occurrences++
		for i := range findings {
			if err := emit(Finding{Blob: key.blob, Report: findings[i]}); err != nil {
				return err
			}
		}
	}
	return nil
}

func hitStats(hits detectionHits) (int64, int64) {
	blobs := make(map[string]struct{})
	type findingID struct {
		blob, rule, secret                         string
		startLine, endLine, startColumn, endColumn int
	}
	findings := make(map[findingID]struct{})
	for key, reports := range hits {
		blobs[key.blob] = struct{}{}
		for _, finding := range reports {
			findings[findingID{
				blob: key.blob, rule: finding.RuleID, secret: finding.Secret,
				startLine: finding.StartLine, endLine: finding.EndLine,
				startColumn: finding.StartColumn, endColumn: finding.EndColumn,
			}] = struct{}{}
		}
	}
	return int64(len(blobs)), int64(len(findings))
}

func printStats(s *scanStats, engine string) {
	fmt.Fprintf(os.Stderr,
		"secrets: %d blobs, %d scanned, %d skipped; %d findings in %d blobs, %d occurrences; detect %s, attribute %s, prefilter %s\n",
		s.total, s.scanned, s.skipped, s.findings, s.hitBlobs, s.occurrences,
		s.blobPhase.Round(time.Millisecond), s.attributePhase.Round(time.Millisecond), engine)
}
