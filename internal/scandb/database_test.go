package scandb

import (
	"testing"

	"github.com/betterleaks/betterleaks/config"
	"github.com/git-pkgs/scan"
)

func TestCompiledRuleIDs(t *testing.T) {
	cfg, err := config.ParseTOMLString(`[[rules]]
id = "z-rule"
description = "Fixture"
regex = 'token[0-9]{4}'
[[rules]]
id = "a-rule"
description = "Fixture"
regex = 'key[0-9]{4}'
`, "fixture.toml")
	if err != nil {
		t.Fatal(err)
	}
	db, err := Compile(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ids := RuleIDs(cfg)
	var matched []string
	err = db.Scan([]byte("key1234 token5678"), nil, func(m scan.Match) error { matched = append(matched, ids[m.ID]); return nil })
	if err != nil {
		t.Fatal(err)
	}
	if len(matched) != 2 || matched[0] != "a-rule" || matched[1] != "z-rule" {
		t.Fatalf("matched=%v", matched)
	}
	before := Hash(cfg)
	delete(cfg.Rules, "z-rule")
	if Hash(cfg) == before {
		t.Fatal("rule hash did not change")
	}
}
