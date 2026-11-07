package internal

// CompiledRegexp is the matching interface used by regexp engines.
type CompiledRegexp interface {
	MatchString(s string) bool
	FindString(s string) string
	FindStringSubmatch(s string) []string
	FindAllStringIndex(s string, n int) [][]int
	ReplaceAllString(src, repl string) string
	NumSubexp() int
	SubexpNames() []string
	String() string
}
