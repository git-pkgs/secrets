package re2_test

import (
	"testing"

	blregexp "github.com/git-pkgs/secrets/betterleaks/regexp"
	scannerre2 "github.com/git-pkgs/secrets/scanner/re2"
)

func TestEnable(t *testing.T) {
	t.Cleanup(func() { blregexp.SetEngine(blregexp.Stdlib{}) })
	scannerre2.Enable()
	if got := blregexp.Version(); got != "re2" {
		t.Fatalf("version=%q", got)
	}
}
