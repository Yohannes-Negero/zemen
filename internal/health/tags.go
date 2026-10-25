package health

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"zemen/internal/attack"
	"zemen/internal/config"
	"zemen/internal/indices"
	"zemen/internal/osclient"
)

// ResolveDetector finds a health record by exact id, or by a unique
// case-insensitive name match.
func ResolveDetector(recs []Record, ref string) (Record, error) {
	var m []Record
	for _, r := range recs {
		if r.DetectorID == ref || strings.EqualFold(r.DetectorName, ref) {
			m = append(m, r)
		}
	}
	switch len(m) {
	case 1:
		return m[0], nil
	case 0:
		return Record{}, fmt.Errorf("no detector matches %q (run 'zemen sync' first, then 'zemen status')", ref)
	default:
		return Record{}, fmt.Errorf("%q is ambiguous (%d matches); use the detector id", ref, len(m))
	}
}

// LoadRecords returns stored health records sorted by name.
func LoadRecords(c *osclient.Client, cfg config.Config) ([]Record, error) {
	hits, err := osclient.AllDocs[Record](c, cfg.IndexName(indices.DetectorHealth))
	if err != nil {
		return nil, err
	}
	out := make([]Record, 0, len(hits))
	for _, h := range hits {
		out = append(out, h.Source)
	}
	sort.Slice(out, func(i, j int) bool {
		return strings.ToLower(out[i].DetectorName) < strings.ToLower(out[j].DetectorName)
	})
	return out, nil
}

// NormalizeTechniques validates, upper-cases and de-duplicates IDs.
func NormalizeTechniques(m *attack.Matrix, in []string) ([]string, error) {
	seen := map[string]bool{}
	out := []string{}
	for _, t := range in {
		t = strings.TrimSpace(t)
		if t == "" {
			continue
		}
		if !attack.Valid(t) {
			return nil, fmt.Errorf("%q is not a valid ATT&CK technique id (expected like T1110 or T1059.001)", t)
		}
		id, par := attack.Normalize(t)
		if !m.Contains(par) {
			return nil, fmt.Errorf("%s is not in the loaded ATT&CK matrix (%s)", par, m.Source)
		}
		if !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	sort.Strings(out)
	return out, nil
}

// SetTags replaces a detector's confirmed ATT&CK techniques.
func SetTags(c *osclient.Client, cfg config.Config, m *attack.Matrix, detectorID string, techniques []string) (Record, error) {
	norm, err := NormalizeTechniques(m, techniques)
	if err != nil {
		return Record{}, err
	}
	idx := cfg.IndexName(indices.DetectorHealth)
	src, found, err := c.GetDoc(idx, detectorID)
	if err != nil {
		return Record{}, err
	}
	if !found {
		return Record{}, fmt.Errorf("detector %s has no health record yet; run 'zemen sync'", detectorID)
	}
	var rec Record
	if err := json.Unmarshal(src, &rec); err != nil {
		return rec, err
	}
	rec.MitreTechniques = norm
	// Drop suggestions that are now confirmed.
	have := map[string]bool{}
	for _, t := range norm {
		_, p := attack.Normalize(t)
		have[p] = true
	}
	var st, sr []string
	for i, s := range rec.SuggestedTechniques {
		if _, p := attack.Normalize(s); !have[p] {
			st = append(st, s)
			if i < len(rec.SuggestionReasons) {
				sr = append(sr, rec.SuggestionReasons[i])
			}
		}
	}
	rec.SuggestedTechniques, rec.SuggestionReasons = nonNil(st), nonNil(sr)
	rec.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	return rec, c.IndexDoc(idx, detectorID, rec)
}

// AcceptSuggestions confirms all (or the listed) suggested techniques.
func AcceptSuggestions(c *osclient.Client, cfg config.Config, m *attack.Matrix, detectorID string, only []string) (Record, error) {
	recs, err := LoadRecords(c, cfg)
	if err != nil {
		return Record{}, err
	}
	rec, err := ResolveDetector(recs, detectorID)
	if err != nil {
		return rec, err
	}
	want := map[string]bool{}
	for _, o := range only {
		_, p := attack.Normalize(o)
		want[p] = true
	}
	merged := append([]string(nil), rec.MitreTechniques...)
	for _, s := range rec.SuggestedTechniques {
		if _, p := attack.Normalize(s); len(want) == 0 || want[p] {
			merged = append(merged, s)
		}
	}
	return SetTags(c, cfg, m, rec.DetectorID, merged)
}
