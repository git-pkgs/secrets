package sources

import (
	"testing"

	"github.com/git-pkgs/secrets/betterleaks/source"
)

func TestSourceAliases(t *testing.T) {
	fragment := Fragment{Attributes: map[string]string{AttrPath: "config.yml"}}
	var core source.Fragment = fragment
	if got := core.Attr(source.AttrPath); got != "config.yml" {
		t.Fatalf("path=%q", got)
	}
	if AttrGitSHA != source.AttrGitSHA || AttrFSSymlink != source.AttrFSSymlink || InnerPathSeparator != source.InnerPathSeparator {
		t.Fatal("shared attribute keys differ")
	}
}
