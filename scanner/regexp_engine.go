package scanner

import (
	blregexp "github.com/git-pkgs/secrets/betterleaks/regexp"
	"github.com/git-pkgs/secrets/betterleaks/regexp/re2"
	"sync"
)

var regexpEngineOnce sync.Once

func init() { configureRegexpEngine() }

func configureRegexpEngine() {
	regexpEngineOnce.Do(func() { blregexp.SetEngine(re2.RE2{}) })
}
