// Package scanner detects secrets in blob bytes without traversing repositories.
package scanner

import (
	"context"
	"errors"
	"math"
	"sync"

	"github.com/git-pkgs/secrets/betterleaks/config"
	"github.com/git-pkgs/secrets/betterleaks/detect"
	"github.com/git-pkgs/secrets/betterleaks/report"
	"github.com/git-pkgs/secrets/betterleaks/sources"
)

// Finding includes the matched rule, secret, source location, and validation details.
type Finding = report.Finding

// Options configures a scanner. The zero value uses the embedded corpus locally.
type Options struct {
	// Config overrides the default corpus. Do not modify it after New.
	Config *config.Config
	// Validation enables outbound credential checks only when Enabled is true.
	Validation  detect.ValidationOptions
	RuleTimings *detect.RuleTimingCollector
}

// Result contains findings and whether text passed the prefilter.
// Binary blobs have Scanned false but can still produce path-only findings.
type Result struct {
	Findings []Finding
	Scanned  bool
}

// Scanner shares its compiled rules and prefilter across concurrent Scan calls.
// Close it after use to release its resources.
type Scanner struct {
	detector  *detect.Detector
	prefilter prefilter
	skip      sources.SkipFunc
	ctx       context.Context
	cancel    context.CancelFunc
	mu        sync.RWMutex
	closed    bool
}

// New constructs a scanner once for any number of blobs.
// Canceling ctx cancels detection and validation in all Scan calls.
func New(ctx context.Context, opts Options) (*Scanner, error) {
	if opts.Validation.Timeout < 0 || opts.Validation.Workers < 0 || opts.Validation.MaxRequestsPerTarget < 0 {
		return nil, errors.New("validation timeout, workers, and request cap must be non-negative")
	}
	for _, rate := range append([]float64{opts.Validation.RequestsPerSecond}, mapValues(opts.Validation.RequestsPerSecondByRule)...) {
		if rate < 0 || math.IsNaN(rate) || math.IsInf(rate, 0) {
			return nil, errors.New("validation request rates must be finite and non-negative")
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	includeLocators := opts.Config == nil
	cfg := opts.Config
	if cfg == nil {
		var err error
		cfg, err = config.Default()
		if err != nil {
			return nil, err
		}
	}
	if err := cfg.CompileFilters(nil); err != nil {
		return nil, err
	}
	pf, err := newPrefilter(cfg, includeLocators)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(ctx)
	d := detect.NewDetectorContext(ctx, cfg, opts.Validation)
	d.RuleTimings = opts.RuleTimings
	return &Scanner{detector: d, prefilter: pf, skip: d.SkipFunc(), ctx: ctx, cancel: cancel}, nil
}

func mapValues(values map[string]float64) []float64 {
	result := make([]float64, 0, len(values))
	for _, value := range values {
		result = append(result, value)
	}
	return result
}

// Scan detects secrets in data. An empty path disables path-based checks.
// Findings contain unredacted secrets. History traversal and OID caching belong to callers.
func (s *Scanner) Scan(ctx context.Context, data []byte, path string) (Result, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return Result{}, errors.New("scanner is closed")
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(s.ctx, cancel)
	defer stop()
	if err := s.ctx.Err(); err != nil {
		return Result{}, err
	}
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	var attrs map[string]string
	if path != "" {
		attrs = map[string]string{sources.AttrPath: path}
	}
	if s.skip != nil && s.skip(attrs) {
		return Result{}, nil
	}
	data, binaryContent := prepareBlob(data)
	findings, candidate := s.prefilter.detect(ctx, s.detector, data, attrs)
	findings, err := s.detector.ValidateFindings(ctx, findings)
	if err != nil {
		return Result{}, err
	}
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	return Result{Findings: findings, Scanned: candidate && !binaryContent}, nil
}

// Engine identifies the embedded or compiled prefilter in use.
func (s *Scanner) Engine() string { return s.prefilter.engine() }

// Close cancels active scans and releases scanner resources. It is idempotent.
func (s *Scanner) Close() error {
	s.cancel()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	if s.detector.ValidationPool != nil {
		s.detector.ValidationPool.Close()
	}
	return s.prefilter.close()
}
