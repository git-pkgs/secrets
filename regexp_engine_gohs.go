//go:build gohs || scan

package main

import (
	blregexp "github.com/betterleaks/betterleaks/regexp"
	"github.com/betterleaks/betterleaks/regexp/re2"
)

func configureRegexpEngine() {
	blregexp.SetEngine(re2.RE2{})
}
