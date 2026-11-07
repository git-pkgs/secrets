package source

import (
	"github.com/git-pkgs/secrets/betterleaks/logging"
	"github.com/rs/zerolog"
)

// Fragment is one piece of content and its source attributes.
type Fragment struct {
	Raw string

	Bytes []byte

	InheritedFromFinding bool

	StartLine int

	Attributes map[string]string
}

func (f *Fragment) SetAttr(key, value string) {
	if f.Attributes == nil {
		f.Attributes = make(map[string]string)
	}
	f.Attributes[key] = value
}

func (f *Fragment) Attr(key string) string {
	if f.Attributes == nil {
		return ""
	}
	return f.Attributes[key]
}

// Logger returns a logger with the fragment's path and commit attributes.
func (f *Fragment) Logger() zerolog.Logger {
	l := logging.With().Str("path", f.Attr(AttrPath))
	if sha := f.Attr(AttrGitSHA); sha != "" {
		l = l.Str("commit", sha)
	}
	return l.Logger()
}

// SetDefaults fills fields whose zero value has no source meaning.
func (f *Fragment) SetDefaults() {
	if f.StartLine == 0 {
		f.StartLine = 1
	}
}
