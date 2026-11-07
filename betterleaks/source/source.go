// Package source defines the fragments consumed by secret detection.
package source

import "context"

// FragmentsFunc receives the next fragment from a source.
type FragmentsFunc func(fragment Fragment, err error) error

// SkipFunc decides whether to discard a fragment from its attributes.
type SkipFunc func(attrs map[string]string) bool

// Source yields fragments for detection.
type Source interface {
	Fragments(ctx context.Context, yield FragmentsFunc) error
}
