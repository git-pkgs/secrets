package scanner

import (
	"context"
	"io"
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
	skip := func(path string) {
		if opts.Skipped != nil {
			mu.Lock()
			opts.Skipped(path)
			mu.Unlock()
		}
	}
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
			skip(path)
			return nil
		}
		g.Go(func() error {
			if err := ctx.Err(); err != nil {
				return err
			}
			data, fits, err := readFile(fsys, path, opts.MaxFileSize)
			if err != nil {
				return err
			}
			if !fits {
				skip(path)
				return nil
			}
			result, err := s.Scan(ctx, data, path)
			if err != nil {
				return err
			}
			mu.Lock()
			defer mu.Unlock()
			return visit(File{Path: path, Size: int64(len(data)), Data: data, Result: result})
		})
		return nil
	})
	if err := g.Wait(); err != nil {
		return err
	}
	return walkErr
}

// readFile reads path, reading at most limit+1 bytes when limit is positive; fits is false when the file is
// longer than limit, which can happen when it grew after the walk read its size.
func readFile(fsys fs.FS, path string, limit int64) (data []byte, fits bool, err error) {
	if limit <= 0 {
		data, err = fs.ReadFile(fsys, path)
		return data, err == nil, err
	}
	f, err := fsys.Open(path)
	if err != nil {
		return nil, false, err
	}
	defer func() { _ = f.Close() }()
	data, err = io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, false, err
	}
	return data, int64(len(data)) <= limit, nil
}
