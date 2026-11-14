package scanner_test

import (
	"context"
	"errors"
	"io/fs"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"testing/fstest"

	"github.com/git-pkgs/secrets/scanner"
)

func TestScanFS(t *testing.T) {
	s := newScanner(t, scanner.Options{})
	freemius := []byte(`"secret_key" => "sk_` + strings.Repeat("A7", 14) + `A"` + "\n")
	fsys := fstest.MapFS{
		"app/config.php": {Data: freemius},
		"app/config.txt": {Data: freemius},
		"token.env":      {Data: []byte("token = " + token + "\n")},
		"big.env":        {Data: []byte("token = " + token + "\n" + strings.Repeat("x", 64))},
		"link.env":       {Data: []byte("token.env"), Mode: fs.ModeSymlink},
	}

	var visited, skipped []string
	found := map[string][]string{}
	err := s.ScanFS(context.Background(), fsys, scanner.FSOptions{
		Workers:     4,
		MaxFileSize: 64,
		Skipped:     func(path string) { skipped = append(skipped, path) },
	}, func(f scanner.File) error {
		visited = append(visited, f.Path)
		for _, finding := range f.Result.Findings {
			found[f.Path] = append(found[f.Path], finding.RuleID)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	slices.Sort(visited)
	if want := []string{"app/config.php", "app/config.txt", "token.env"}; !slices.Equal(visited, want) {
		t.Errorf("visited %q, want %q", visited, want)
	}
	if !slices.Equal(skipped, []string{"big.env"}) {
		t.Errorf("skipped %q, want big.env", skipped)
	}
	if len(found) != 2 || !slices.Equal(found["app/config.php"], []string{"freemius-secret-key"}) || !slices.Equal(found["token.env"], []string{"github-pat"}) {
		t.Errorf("findings %v", found)
	}
}

func TestScanFSReturnsVisitError(t *testing.T) {
	s := newScanner(t, scanner.Options{})
	stop := errors.New("stop")
	fsys := fstest.MapFS{"a.env": {Data: []byte("token = " + token + "\n")}}
	err := s.ScanFS(context.Background(), fsys, scanner.FSOptions{}, func(scanner.File) error { return stop })
	if !errors.Is(err, stop) {
		t.Fatalf("err = %v, want visit error", err)
	}
}

// readCountFS counts the files read from it.
type readCountFS struct {
	fstest.MapFS
	reads *atomic.Int32
}

func (c readCountFS) Open(name string) (fs.File, error) {
	if name != "." {
		c.reads.Add(1)
	}
	return c.MapFS.Open(name)
}

func (c readCountFS) ReadFile(name string) ([]byte, error) {
	c.reads.Add(1)
	return c.MapFS.ReadFile(name)
}

func TestScanFSStopsReadingAfterVisitError(t *testing.T) {
	s := newScanner(t, scanner.Options{})
	stop := errors.New("stop")
	fsys := readCountFS{MapFS: fstest.MapFS{
		"a.env": {Data: []byte("token = " + token + "\n")},
		"b.env": {Data: []byte("token = " + token + "\n")},
	}, reads: new(atomic.Int32)}
	err := s.ScanFS(context.Background(), fsys, scanner.FSOptions{Workers: 1}, func(scanner.File) error { return stop })
	if !errors.Is(err, stop) {
		t.Fatalf("err = %v, want visit error", err)
	}
	if n := fsys.reads.Load(); n != 1 {
		t.Fatalf("read %d files after the first visit failed, want 1", n)
	}
}

// staleSizeFS reports every file as 1 byte long during the walk, as if it grew afterwards.
type staleSizeFS struct{ fstest.MapFS }

func (s staleSizeFS) ReadDir(name string) ([]fs.DirEntry, error) {
	entries, err := s.MapFS.ReadDir(name)
	for i, e := range entries {
		entries[i] = staleEntry{e}
	}
	return entries, err
}

type staleEntry struct{ fs.DirEntry }

func (e staleEntry) Info() (fs.FileInfo, error) {
	info, err := e.DirEntry.Info()
	return staleInfo{info}, err
}

type staleInfo struct{ fs.FileInfo }

func (staleInfo) Size() int64 { return 1 }

func TestScanFSSkipsFileThatGrewPastMaxFileSize(t *testing.T) {
	s := newScanner(t, scanner.Options{})
	fsys := staleSizeFS{fstest.MapFS{"big.env": {Data: []byte("token = " + token + "\n" + strings.Repeat("x", 64))}}}
	var visited, skipped []string
	err := s.ScanFS(context.Background(), fsys, scanner.FSOptions{
		MaxFileSize: 64,
		Skipped:     func(path string) { skipped = append(skipped, path) },
	}, func(f scanner.File) error {
		visited = append(visited, f.Path)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(visited) != 0 || !slices.Equal(skipped, []string{"big.env"}) {
		t.Fatalf("visited %v, skipped %v; want big.env skipped", visited, skipped)
	}
}
