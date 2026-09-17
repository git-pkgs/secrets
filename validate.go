package main

import (
	"context"
	"sync/atomic"

	"github.com/betterleaks/betterleaks/detect"
	"github.com/betterleaks/betterleaks/sources"
	"github.com/git-pkgs/history"
)

// blobSource adapts history.WalkBlobs to betterleaks' sources.Source so the
// detector's Run pipeline (which owns the async validation pool) can drive
// the scan.
type blobSource struct {
	repo             *history.Repo
	pf               prefilter
	paths            map[string][]string
	skip             sources.SkipFunc
	scanned, skipped *atomic.Int64
	total            *int64
}

const attrBlobOID = "git-pkgs.blob-oid"

func (s *blobSource) Fragments(ctx context.Context, yield sources.FragmentsFunc) error {
	total, err := s.repo.WalkBlobs(history.BlobOptions{
		Workers: workers,
		Limit:   func(string) int64 { return maxBlobSize },
		Skip:    func(string) { s.skipped.Add(1) },
	}, func(b history.Blob) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		data, binaryContent := prepareBlob(b.Data)
		contentMatched := !binaryContent && s.pf.match(data)

		paths := s.paths[b.OID]
		if s.paths == nil {
			paths = []string{""}
		}
		scanned := false
		for _, path := range paths {
			if err := ctx.Err(); err != nil {
				return err
			}
			attributes := map[string]string{attrBlobOID: b.OID}
			if path != "" {
				attributes[sources.AttrPath] = path
			}
			if s.skip != nil && s.skip(attributes) {
				continue
			}
			pathMatched := s.pf.pathMatch(path)
			if binaryContent && !pathMatched {
				continue
			}
			if !binaryContent && !contentMatched && !pathMatched {
				continue
			}
			if !binaryContent && !scanned {
				s.scanned.Add(1)
				scanned = true
			}
			if err := yield(sources.Fragment{Raw: string(data), Attributes: attributes}, nil); err != nil {
				return err
			}
		}
		if binaryContent || !scanned {
			s.skipped.Add(1)
		}
		return nil
	})
	*s.total = int64(total)
	return err
}

// detectBlobsRun uses detector.Run so validation is applied.
func detectBlobsRun(ctx context.Context, r *history.Repo, d *detect.Detector, pf prefilter, paths map[string][]string, stats *scanStats) (detectionHits, error) {
	var scanned, skipped atomic.Int64
	src := &blobSource{
		repo: r, pf: pf, paths: paths, skip: d.SkipFunc(),
		scanned: &scanned, skipped: &skipped, total: &stats.total,
	}
	hits := make(detectionHits)
	for result := range d.Run(ctx, src) {
		if result.Err != nil {
			stats.scanned, stats.skipped = scanned.Load(), skipped.Load()
			return hits, result.Err
		}
		key := blobPath{
			blob: result.Finding.Attr(attrBlobOID),
			path: result.Finding.Attr(sources.AttrPath),
		}
		hits[key] = append(hits[key], result.Finding)
	}
	stats.scanned, stats.skipped = scanned.Load(), skipped.Load()
	if err := ctx.Err(); err != nil {
		return hits, err
	}
	return hits, nil
}
