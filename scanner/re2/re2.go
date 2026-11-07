// Package re2 enables the RE2 regexp engine for subsequent scanner creation.
package re2

import (
	blregexp "github.com/git-pkgs/secrets/betterleaks/regexp"
	blre2 "github.com/git-pkgs/secrets/betterleaks/regexp/re2"
)

// Enable selects RE2 for regular expressions compiled after this call.
func Enable() {
	blregexp.SetEngine(blre2.RE2{})
}
