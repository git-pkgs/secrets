package scanner

import (
	"context"
	"io/fs"
	"sync"

	"golang.org/x/sync/errgroup"
)

// FSOptions configures ScanFS. A zero MaxFileSize scans files of any size.
type FSOptions struct {
	Workers     int
	MaxFileSize int64
	// Skipped is called for each regular file larger than MaxFileSize.
	Skipped func(path string)
}

// File is the result of scanning one file. Path is slash-separated and relative to the FS root.
type File struct {
	Path   string
	Size   int64
	Data   []byte
	Result Result
}

// ScanFS scans every regular file in fsys and calls visit once per scanned file, one call at a time.
// Symlinks, directories and other non-regular files are not read.
func (s *Scanner) ScanFS(ctx context.Context, fsys fs.FS, opts FSOptions, visit func(File) error) error {
	g, ctx := errgroup.WithContext(ctx)
	g.SetLimit(max(opts.Workers, 1))
	var mu sync.Mutex
	walkErr := fs.WalkDir(fsys, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if !d.Type().IsRegular() {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		if opts.MaxFileSize > 0 && info.Size() > opts.MaxFileSize {
			if opts.Skipped != nil {
				mu.Lock()
				opts.Skipped(path)
				mu.Unlock()
			}
			return nil
		}
		g.Go(func() error {
			data, err := fs.ReadFile(fsys, path)
			if err != nil {
				return err
			}
			result, err := s.Scan(ctx, data, path)
			if err != nil {
				return err
			}
			mu.Lock()
			defer mu.Unlock()
			return visit(File{Path: path, Size: info.Size(), Data: data, Result: result})
		})
		return nil
	})
	if err := g.Wait(); err != nil {
		return err
	}
	return walkErr
}
