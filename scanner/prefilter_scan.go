//go:build !gohs

package scanner

import (
	"bytes"
	"compress/gzip"
	"context"
	_ "embed"
	"encoding/binary"
	"fmt"
	"io"
	"strings"
	"sync"

	"github.com/git-pkgs/scan"
	"github.com/git-pkgs/secrets/betterleaks/config"
	"github.com/git-pkgs/secrets/betterleaks/detect"
	"github.com/git-pkgs/secrets/betterleaks/report"
	sources "github.com/git-pkgs/secrets/betterleaks/source"
	"github.com/git-pkgs/secrets/internal/scandb"
)

//go:generate go run ../cmd/genscandb -output scan.db.gz

//go:embed scan.db.gz
var embeddedScanDB []byte

//go:embed scan.db.gz.sha256
var embeddedScanHash string

type prefilter struct {
	db            *scan.Database
	pool          *sync.Pool
	engineName    string
	ruleIDs       []string
	locatorIDs    []string
	pathOnlyRules []config.Rule
}

const (
	gzipFooterSize        = 4
	maxEmbeddedScanDBSize = 64 << 20
)

func newPrefilter(cfg *config.Config, includeLocators bool) (prefilter, error) {
	var db *scan.Database
	var err error
	engineName := "scan-compiled"
	if includeLocators && strings.TrimSpace(embeddedScanHash) == scandb.Hash(cfg, true) {
		db, err = unmarshalCompressedDatabase(embeddedScanDB)
		if err != nil {
			return prefilter{}, err
		}
		engineName = "scan-embedded"
	} else {
		db, err = scandb.Compile(cfg, includeLocators)
		if err != nil {
			return prefilter{}, err
		}
	}
	pool := &sync.Pool{New: func() any { return scan.NewScratch(db) }}
	return prefilter{db: db, pool: pool, engineName: engineName, ruleIDs: scandb.RuleIDs(cfg), locatorIDs: scandb.LocatorRuleIDs(cfg, includeLocators), pathOnlyRules: configuredPathOnlyRules(cfg)}, nil
}

func unmarshalCompressedDatabase(data []byte) (*scan.Database, error) {
	if len(data) < gzipFooterSize {
		return nil, io.ErrUnexpectedEOF
	}
	size := int(binary.LittleEndian.Uint32(data[len(data)-gzipFooterSize:]))
	if size == 0 || size > maxEmbeddedScanDBSize {
		return nil, fmt.Errorf("embedded scan database size %d is invalid", size)
	}
	reader, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	var decompressed bytes.Buffer
	decompressed.Grow(size)
	_, copyErr := io.Copy(&decompressed, reader)
	closeErr := reader.Close()
	if copyErr != nil {
		return nil, copyErr
	}
	if closeErr != nil {
		return nil, closeErr
	}
	if decompressed.Len() != size {
		return nil, fmt.Errorf("embedded scan database size is %d, expected %d", decompressed.Len(), size)
	}
	return scan.UnmarshalDatabase(decompressed.Bytes())
}

func (p prefilter) detect(ctx context.Context, d *detect.Detector, data []byte, attributes map[string]string) ([]report.Finding, bool) {
	fragment := sources.Fragment{Raw: string(data), Attributes: attributes}
	if p.db == nil {
		return d.DetectFragment(ctx, fragment), true
	}
	scratch := p.pool.Get().(*scan.Scratch)
	defer p.pool.Put(scratch)
	var ids []string
	seen := make([]bool, len(p.ruleIDs))
	locations := make(map[string][]byteRange)
	err := p.db.Scan(data, scratch, func(match scan.Match) error {
		id, to := match.ID, match.To
		if int(id) < len(p.ruleIDs) {
			if !seen[id] {
				seen[id] = true
				ids = append(ids, p.ruleIDs[id])
			}
			return nil
		}
		locator := int(id) - len(p.ruleIDs)
		if locator >= 0 && locator < len(p.locatorIDs) && to <= uint64(len(data)) {
			ruleID := p.locatorIDs[locator]
			padding := locatorPadding(ruleID)
			locations[ruleID] = append(locations[ruleID], byteRange{start: max(int(to)-padding, 0), end: min(int(to)+padding, len(data))})
		}
		return nil
	})
	if err != nil {
		return d.DetectFragment(ctx, fragment), true
	}
	path := fragment.Attr(sources.AttrPath)
	for _, rule := range p.pathOnlyRules {
		if path != "" && rule.Path.MatchString(path) {
			ids = append(ids, rule.RuleID)
		}
	}
	if len(ids) == 0 {
		return nil, false
	}
	windows := make(map[string][]detect.RuleWindow, len(locations))
	for ruleID, ranges := range locations {
		windows[ruleID] = normalizeWindows(data, ranges)
	}
	return d.DetectFragmentRuleWindows(ctx, fragment, ids, windows), true
}

func (p prefilter) engine() string { return p.engineName }

func (*prefilter) close() error { return nil }
