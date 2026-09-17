//go:build gohs || scan

package main

import (
	"bytes"
	"sort"

	"github.com/betterleaks/betterleaks/detect"
)

const (
	passwordLocatorPadding = 8192
	defaultLocatorPadding  = 512
)

type byteRange struct {
	start int
	end   int
}

func locatorPadding(ruleID string) int {
	if ruleID == "generic-password" {
		return passwordLocatorPadding
	}
	return defaultLocatorPadding
}

func normalizeWindows(data []byte, ranges []byteRange) []detect.RuleWindow {
	if len(ranges) == 0 {
		return nil
	}
	sort.Slice(ranges, func(i, j int) bool { return ranges[i].start < ranges[j].start })
	merged := ranges[:0]
	for _, current := range ranges {
		if len(merged) == 0 || current.start > merged[len(merged)-1].end {
			merged = append(merged, current)
			continue
		}
		merged[len(merged)-1].end = max(merged[len(merged)-1].end, current.end)
	}

	windows := make([]detect.RuleWindow, 0, len(merged))
	for _, current := range merged {
		start := 0
		if newline := bytes.LastIndexByte(data[:current.start], '\n'); newline >= 0 {
			start = newline + 1
		}
		end := len(data)
		if newline := bytes.IndexByte(data[current.end:], '\n'); newline >= 0 {
			end = current.end + newline + 1
		}
		window := detect.RuleWindow{
			Start: start, End: end,
			StartLine: bytes.Count(data[:start], []byte{'\n'}) + 1,
		}
		if len(windows) > 0 && window.Start <= windows[len(windows)-1].End {
			windows[len(windows)-1].End = max(windows[len(windows)-1].End, window.End)
			continue
		}
		windows = append(windows, window)
	}
	return windows
}
