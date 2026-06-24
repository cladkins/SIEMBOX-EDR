package detect

import (
	"embed"
	"fmt"
	"strings"
)

//go:embed rules/*.yml
var defaultRulesFS embed.FS

// DefaultRules returns the embedded default Sigma rule pack as YAML documents.
// The agent loads these alongside any rules pushed by the SIEMBox server.
func DefaultRules() ([]string, error) {
	entries, err := defaultRulesFS.ReadDir("rules")
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".yml") {
			continue
		}
		b, err := defaultRulesFS.ReadFile("rules/" + e.Name())
		if err != nil {
			return nil, fmt.Errorf("read embedded rule %s: %w", e.Name(), err)
		}
		out = append(out, string(b))
	}
	return out, nil
}
