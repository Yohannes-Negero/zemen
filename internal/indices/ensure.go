package indices

import (
	"fmt"

	"zemen/internal/config"
	"zemen/internal/osclient"
)

// Result describes what happened for one logical index.
type Result struct {
	Logical, Physical string
	Created           bool
	Extended          bool // already existed; new fields were added
	Warning           string
	Err               error
}

// EnsureAll creates missing indices and additively extends existing ones
// (so indices created by an older Zemen version gain the new fields).
// It is safe to run repeatedly.
func EnsureAll(c *osclient.Client, cfg config.Config) []Result {
	out := make([]Result, 0, len(All))
	for _, logical := range All {
		r := Result{Logical: logical, Physical: cfg.IndexName(logical)}
		exists, err := c.IndexExists(r.Physical)
		if err != nil {
			r.Err = fmt.Errorf("checking index %s: %w", r.Physical, err)
			out = append(out, r)
			continue
		}
		if !exists {
			if err := c.CreateIndex(r.Physical, Mapping(logical)); err != nil {
				r.Err = fmt.Errorf("creating index %s: %w", r.Physical, err)
			} else {
				r.Created = true
			}
			out = append(out, r)
			continue
		}
		if err := c.PutMapping(r.Physical, Properties(logical)); err != nil {
			// Not fatal: a type conflict with an older mapping just means
			// that one field keeps its old type.
			r.Warning = fmt.Sprintf("could not extend mapping: %v", err)
		} else {
			r.Extended = true
		}
		out = append(out, r)
	}
	return out
}
