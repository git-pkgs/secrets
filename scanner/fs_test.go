package scanner_test

import (
	"context"
	"errors"
	"io/fs"
	"slices"
	"strings"
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
