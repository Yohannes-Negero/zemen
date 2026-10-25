// Package replay is Replay Court (proposal section 7.1): a library of
// recorded or synthetic log sequences that are replayed into an index the
// mapped detectors watch, then verified by checking that each detector
// actually produced a finding for the replayed documents. It turns
// "we think this detector still works" into a dated pass/fail fact.
package replay

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"zemen/internal/attack"
	"zemen/internal/config"
	"zemen/internal/indices"
	"zemen/internal/osclient"
	"zemen/internal/secanalytics"
)

// Case is the self-service case format (zemen-data/replay_cases/*.json).
type Case struct {
	CaseID               string           `json:"case_id"`
	TechniqueID          string           `json:"technique_id"`
	Description          string           `json:"description"`
	TargetIndex          string           `json:"target_index"`
	MappedDetectors      []string         `json:"mapped_detectors"` // detector names or ids
	Events               []map[string]any `json:"events"`
	AllowProductionIndex bool             `json:"allow_production_index,omitempty"`
	Cleanup              *bool            `json:"cleanup,omitempty"` // default true
	Notes                string           `json:"notes,omitempty"`
}

// DetectorResult is one detector's verdict for one run.
type DetectorResult struct {
	DetectorID     string  `json:"detector_id"`
	DetectorName   string  `json:"detector_name"`
	Passed         bool    `json:"passed"`
	FindingID      string  `json:"finding_id,omitempty"`
	LatencySeconds float64 `json:"latency_seconds,omitempty"`
	CheckedAt      string  `json:"checked_at"`
	LastPassAt     string  `json:"last_pass_at,omitempty"`
	Error          string  `json:"error,omitempty"`
}

// Stored is a case as persisted, with its last results.
type Stored struct {
	Case
	MappedDetectorIDs []string
	Results           []DetectorResult
	LastOverall       string
	LastRunAt         string
	LastPassAt        string
}

type doc struct {
	CaseID               string   `json:"case_id"`
	TechniqueID          string   `json:"technique_id"`
	Description          string   `json:"description"`
	TargetIndex          string   `json:"target_index"`
	MappedDetectors      []string `json:"mapped_detectors"`
	MappedDetectorIDs    []string `json:"mapped_detector_ids"`
	EventsJSON           string   `json:"events_json"`
	LastResultJSON       string   `json:"last_result_json,omitempty"`
	AllowProductionIndex bool     `json:"allow_production_index"`
	LastOverall          string   `json:"last_overall,omitempty"`
	LastRunAt            string   `json:"last_run_at,omitempty"`
	LastPassAt           string   `json:"last_pass_at,omitempty"`
	SourceFile           string   `json:"source_file,omitempty"`
	CreatedAt            string   `json:"created_at"`
	UpdatedAt            string   `json:"updated_at"`
}

// Template returns a blank, documented case.
func Template() Case {
	return Case{
		CaseID: "my-case-id", TechniqueID: "T1110",
		Description:     "What attack behavior this replays and why the mapped detector should catch it.",
		TargetIndex:     "my-logs-zemen-replay",
		MappedDetectors: []string{"Name of the detector expected to fire"},
		Events: []map[string]any{{
			"@timestamp": "{{now}}",
			"message":    "an event shaped exactly like your real log lines",
			"log_type":   "postgresql",
		}},
		Notes: "target_index must match one of the mapped detector's input index patterns (e.g. detector watches my-logs*). {{now}} is replaced with the current time.",
	}
}

// LoadDir reads every *.json file (a case object or an array of cases).
func LoadDir(dir string) ([]Case, []error) {
	files, _ := filepath.Glob(filepath.Join(dir, "*.json"))
	sort.Strings(files)
	var cases []Case
	var errs []error
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		var many []Case
		if err := json.Unmarshal(b, &many); err != nil {
			var one Case
			if err2 := json.Unmarshal(b, &one); err2 != nil {
				errs = append(errs, fmt.Errorf("%s: %w", filepath.Base(f), err2))
				continue
			}
			many = []Case{one}
		}
		cases = append(cases, many...)
	}
	return cases, errs
}

// Validate checks a case and resolves its detectors.
func Validate(c Case, dets []secanalytics.Detector, m *attack.Matrix) ([]secanalytics.Detector, error) {
	if strings.TrimSpace(c.CaseID) == "" {
		return nil, fmt.Errorf("case_id is required")
	}
	if len(c.Events) == 0 {
		return nil, fmt.Errorf("case %s: events must contain at least one event", c.CaseID)
	}
	if c.TargetIndex == "" {
		return nil, fmt.Errorf("case %s: target_index is required", c.CaseID)
	}
	if c.TechniqueID != "" {
		if !attack.Valid(c.TechniqueID) {
			return nil, fmt.Errorf("case %s: technique_id %q is not a valid ATT&CK id", c.CaseID, c.TechniqueID)
		}
		if _, p := attack.Normalize(c.TechniqueID); m != nil && !m.Contains(p) {
			return nil, fmt.Errorf("case %s: %s is not in the loaded ATT&CK matrix", c.CaseID, p)
		}
	}
	if len(c.MappedDetectors) == 0 {
		return nil, fmt.Errorf("case %s: mapped_detectors must name at least one detector", c.CaseID)
	}
	var out []secanalytics.Detector
	for _, ref := range c.MappedDetectors {
		var found *secanalytics.Detector
		for i := range dets {
			if dets[i].ID == ref || strings.EqualFold(dets[i].Name, ref) {
				found = &dets[i]
				break
			}
		}
		if found == nil {
			return nil, fmt.Errorf("case %s: no detector matches %q", c.CaseID, ref)
		}
		if !found.Enabled {
			return nil, fmt.Errorf("case %s: detector %q is disabled; a disabled detector cannot fire", c.CaseID, found.Name)
		}
		match, exact := false, false
		for _, p := range found.InputIndices {
			if osclient.Wildcard(p, c.TargetIndex) {
				match = true
				if p == c.TargetIndex {
					exact = true
				}
			}
		}
		if !match {
			return nil, fmt.Errorf("case %s: detector %q watches %v, which does not include target_index %q", c.CaseID, found.Name, found.InputIndices, c.TargetIndex)
		}
		if exact && !strings.Contains(c.TargetIndex, "*") && !c.AllowProductionIndex {
			return nil, fmt.Errorf("case %s: target_index %q is exactly the index %q watches in production. Replayed events would be mixed into real logs. Use a separate index matching a wildcard pattern (e.g. %s-zemen-replay) or set allow_production_index to true if you accept that", c.CaseID, c.TargetIndex, found.Name, c.TargetIndex)
		}
		if !c.AllowProductionIndex && !strings.Contains(strings.ToLower(c.TargetIndex), "replay") {
			return nil, fmt.Errorf("case %s: target_index %q does not look like a replay index. Replay events must go to a dedicated index whose name contains 'replay' (for example %s-zemen-replay), so they can never be mixed into real logs. Set allow_production_index to true only if you really mean it", c.CaseID, c.TargetIndex, strings.TrimSuffix(c.TargetIndex, "*"))
		}
		out = append(out, *found)
	}
	return out, nil
}

// RunOutcome is the result of running one case.
type RunOutcome struct {
	CaseID   string
	RunID    string
	Overall  string // pass | fail | partial | error
	Results  []DetectorResult
	Warnings []string
}

func render(ev map[string]any, now time.Time, runID string) map[string]any {
	out := map[string]any{}
	for k, v := range ev {
		if s, ok := v.(string); ok {
			s = strings.ReplaceAll(s, "{{now}}", now.UTC().Format("2006-01-02T15:04:05.000Z"))
			s = strings.ReplaceAll(s, "{{run_id}}", runID)
			out[k] = s
		} else {
			out[k] = v
		}
	}
	return out
}

// Run replays a validated case and waits for each mapped detector to fire.
func Run(c *osclient.Client, cfg config.Config, cs Case, dets []secanalytics.Detector, prior []DetectorResult) (RunOutcome, error) {
	runID := fmt.Sprintf("%d", time.Now().UnixNano()/1e6)
	out := RunOutcome{CaseID: cs.CaseID, RunID: runID}
	start := time.Now()

	var items []osclient.BulkItem
	ids := map[string]bool{}
	for i, ev := range cs.Events {
		id := fmt.Sprintf("zemen-replay-%s-%s-%d", cs.CaseID, runID, i)
		d := render(ev, start, runID)
		d["zemen_replay"] = map[string]any{"run_id": runID, "case_id": cs.CaseID}
		items = append(items, osclient.BulkItem{Action: "index", Index: cs.TargetIndex, ID: id, Doc: d})
		ids[id] = true
	}
	fails, err := c.Bulk(items, true)
	if err != nil {
		return out, fmt.Errorf("indexing replay events into %s: %w", cs.TargetIndex, err)
	}
	if len(fails) > 0 {
		return out, fmt.Errorf("replay events rejected by %s: %s", cs.TargetIndex, fails[0])
	}

	if cfg.ReplayTrigger {
		for _, d := range dets {
			for _, wf := range d.WorkflowIDs {
				if _, err := c.Post("/_plugins/_alerting/workflows/"+wf+"/_execute", map[string]any{}); err != nil {
					out.Warnings = append(out.Warnings, fmt.Sprintf("could not trigger workflow %s: %v (relying on the detector's own schedule)", wf, err))
				}
			}
		}
	}

	pending := map[string]secanalytics.Detector{}
	for _, d := range dets {
		pending[d.ID] = d
	}
	results := map[string]DetectorResult{}
	deadline := start.Add(cfg.ReplayWait)
	for {
		fr, err := secanalytics.FetchFindings(c, 500)
		if err == nil {
			for _, f := range fr.Findings {
				d, ok := pending[f.DetectorID]
				if !ok {
					continue
				}
				for _, r := range f.RelatedDocIDs {
					if ids[r] {
						results[d.ID] = DetectorResult{DetectorID: d.ID, DetectorName: d.Name, Passed: true, FindingID: f.ID,
							LatencySeconds: float64(f.Timestamp-start.UnixMilli()) / 1000, CheckedAt: time.Now().UTC().Format(time.RFC3339)}
						delete(pending, d.ID)
						break
					}
				}
			}
		} else {
			out.Warnings = append(out.Warnings, "polling findings failed: "+err.Error())
		}
		if len(pending) == 0 || time.Now().After(deadline) {
			break
		}
		time.Sleep(cfg.ReplayPollInterval)
	}

	now := time.Now().UTC().Format(time.RFC3339)
	prev := map[string]DetectorResult{}
	for _, p := range prior {
		prev[p.DetectorID] = p
	}
	pass := 0
	for _, d := range dets {
		r, ok := results[d.ID]
		if !ok {
			r = DetectorResult{DetectorID: d.ID, DetectorName: d.Name, CheckedAt: now,
				Error: fmt.Sprintf("no finding referencing the replayed documents appeared within %s", cfg.ReplayWait)}
		}
		if r.Passed {
			r.LastPassAt = now
			pass++
		} else if p, ok := prev[d.ID]; ok {
			r.LastPassAt = p.LastPassAt
		}
		out.Results = append(out.Results, r)
	}
	switch {
	case pass == len(dets):
		out.Overall = "pass"
	case pass == 0:
		out.Overall = "fail"
	default:
		out.Overall = "partial"
	}

	if cs.Cleanup == nil || *cs.Cleanup {
		var del []osclient.BulkItem
		for id := range ids {
			del = append(del, osclient.BulkItem{Action: "delete", Index: cs.TargetIndex, ID: id})
		}
		if _, err := c.Bulk(del, true); err != nil {
			out.Warnings = append(out.Warnings, "cleanup of replay documents failed: "+err.Error())
		}
	}
	return out, nil
}

// Save persists a case (upsert), preserving previous results.
func Save(c *osclient.Client, cfg config.Config, cs Case, detIDs []string, source string) error {
	idx := cfg.IndexName(indices.ReplayCase)
	d := doc{CaseID: cs.CaseID, TechniqueID: strings.ToUpper(cs.TechniqueID), Description: cs.Description, TargetIndex: cs.TargetIndex,
		MappedDetectors: cs.MappedDetectors, MappedDetectorIDs: detIDs, AllowProductionIndex: cs.AllowProductionIndex, SourceFile: source}
	eb, _ := json.Marshal(struct {
		Events  []map[string]any `json:"events"`
		Cleanup *bool            `json:"cleanup,omitempty"`
		Notes   string           `json:"notes,omitempty"`
	}{cs.Events, cs.Cleanup, cs.Notes})
	d.EventsJSON = string(eb)
	now := time.Now().UTC().Format(time.RFC3339)
	d.CreatedAt, d.UpdatedAt = now, now
	if src, found, err := c.GetDoc(idx, cs.CaseID); err != nil {
		return err
	} else if found {
		var old doc
		if json.Unmarshal(src, &old) == nil {
			d.CreatedAt = old.CreatedAt
			d.LastResultJSON, d.LastOverall, d.LastRunAt, d.LastPassAt = old.LastResultJSON, old.LastOverall, old.LastRunAt, old.LastPassAt
		}
	}
	return c.IndexDoc(idx, cs.CaseID, d)
}

// SaveOutcome records a run's results on the stored case.
func SaveOutcome(c *osclient.Client, cfg config.Config, o RunOutcome) error {
	idx := cfg.IndexName(indices.ReplayCase)
	src, found, err := c.GetDoc(idx, o.CaseID)
	if err != nil || !found {
		return fmt.Errorf("case %s not stored", o.CaseID)
	}
	var d doc
	if err := json.Unmarshal(src, &d); err != nil {
		return err
	}
	rb, _ := json.Marshal(o.Results)
	now := time.Now().UTC().Format(time.RFC3339)
	d.LastResultJSON, d.LastOverall, d.LastRunAt, d.UpdatedAt = string(rb), o.Overall, now, now
	if o.Overall == "pass" {
		d.LastPassAt = now
	}
	return c.IndexDoc(idx, o.CaseID, d)
}

// LoadStored returns every stored case, sorted by id.
func LoadStored(c *osclient.Client, cfg config.Config) ([]Stored, error) {
	hits, err := osclient.AllDocs[doc](c, cfg.IndexName(indices.ReplayCase))
	if err != nil {
		return nil, err
	}
	var out []Stored
	for _, h := range hits {
		d := h.Source
		s := Stored{MappedDetectorIDs: d.MappedDetectorIDs, LastOverall: d.LastOverall, LastRunAt: d.LastRunAt, LastPassAt: d.LastPassAt}
		s.CaseID, s.TechniqueID, s.Description, s.TargetIndex = d.CaseID, d.TechniqueID, d.Description, d.TargetIndex
		s.MappedDetectors, s.AllowProductionIndex = d.MappedDetectors, d.AllowProductionIndex
		var ev struct {
			Events  []map[string]any `json:"events"`
			Cleanup *bool            `json:"cleanup"`
			Notes   string           `json:"notes"`
		}
		if json.Unmarshal([]byte(d.EventsJSON), &ev) == nil {
			s.Events, s.Cleanup, s.Notes = ev.Events, ev.Cleanup, ev.Notes
		}
		if d.LastResultJSON != "" {
			_ = json.Unmarshal([]byte(d.LastResultJSON), &s.Results)
		}
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CaseID < out[j].CaseID })
	return out, nil
}

// VerifiedTechniques returns parent technique IDs with a fully passing
// run within the last days, plus per-detector last pass times.
func VerifiedTechniques(cases []Stored, days int, now time.Time) (map[string]bool, map[string]map[string]time.Time) {
	ver := map[string]bool{}
	perDet := map[string]map[string]time.Time{} // detector -> parent technique -> last pass
	for _, c := range cases {
		if c.TechniqueID == "" {
			continue
		}
		_, par := attack.Normalize(c.TechniqueID)
		for _, r := range c.Results {
			if r.LastPassAt == "" {
				continue
			}
			t, err := time.Parse(time.RFC3339, r.LastPassAt)
			if err != nil {
				continue
			}
			if perDet[r.DetectorID] == nil {
				perDet[r.DetectorID] = map[string]time.Time{}
			}
			if t.After(perDet[r.DetectorID][par]) {
				perDet[r.DetectorID][par] = t
			}
		}
		if c.LastOverall == "pass" {
			if t, err := time.Parse(time.RFC3339, c.LastPassAt); err == nil && now.Sub(t) <= time.Duration(days)*24*time.Hour {
				ver[par] = true
			}
		}
	}
	return ver, perDet
}

// ExampleCases are written by `zemen init`, matching PostgreSQL logs of
// the shape the Phase 0 testing cluster used (message field + log_type).
func ExampleCases() []Case {
	return []Case{
		{CaseID: "postgres-sql-injection-tautology", TechniqueID: "T1190",
			Description: "A SQL tautology (OR 1=1) executed against PostgreSQL, as a SQL injection probe would.",
			TargetIndex: "postgres-logs-zemen-replay", MappedDetectors: []string{"REPLACE-WITH-YOUR-DETECTOR-NAME"},
			Events: []map[string]any{{"@timestamp": "{{now}}", "log_type": "postgresql",
				"message": "2026-01-01 10:00:00.000 EAT [1111] postgres@postgres ::1 LOG:  statement: select * from accounts where id=1 OR 1=1"}},
			Notes: "Edit mapped_detectors, and make sure the detector's input index pattern matches postgres-logs* (not only the exact name postgres-logs)."},
		{CaseID: "postgres-brute-force-auth-failures", TechniqueID: "T1110",
			Description: "Repeated PostgreSQL authentication failures, as a brute-force attempt would produce.",
			TargetIndex: "postgres-logs-zemen-replay", MappedDetectors: []string{"REPLACE-WITH-YOUR-DETECTOR-NAME"},
			Events: []map[string]any{
				{"@timestamp": "{{now}}", "log_type": "postgresql", "message": "2026-01-01 10:00:01.000 EAT [2222] postgres@postgres ::1 FATAL:  password authentication failed for user \"postgres\""},
				{"@timestamp": "{{now}}", "log_type": "postgresql", "message": "2026-01-01 10:00:02.000 EAT [2223] postgres@postgres ::1 FATAL:  password authentication failed for user \"postgres\""},
				{"@timestamp": "{{now}}", "log_type": "postgresql", "message": "2026-01-01 10:00:03.000 EAT [2224] postgres@postgres ::1 FATAL:  password authentication failed for user \"postgres\""},
			}},
	}
}
