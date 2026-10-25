// Package lineage is Detector Lineage & Biography (proposal section 7.2).
// Every detector accumulates a narrative history: when Zemen first saw it,
// every definition change (detected automatically by diffing snapshots),
// every status transition, replay regressions, and human-written reasons.
package lineage

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"zemen/internal/config"
	"zemen/internal/health"
	"zemen/internal/indices"
	"zemen/internal/osclient"
	"zemen/internal/replay"
	"zemen/internal/secanalytics"
)

// Entry is one lineage record.
type Entry struct {
	DetectorID    string   `json:"detector_id"`
	ChangeID      string   `json:"change_id"`
	ChangedAt     string   `json:"changed_at"`
	Reason        string   `json:"reason"`
	TriggerEvent  string   `json:"trigger_event,omitempty"`
	Author        string   `json:"author"`
	Kind          string   `json:"kind"`
	ChangedFields []string `json:"changed_fields,omitempty"`
	PendingReason bool     `json:"pending_reason,omitempty"`
	SnapshotHash  string   `json:"snapshot_hash,omitempty"`
}

type snapshot struct {
	DetectorID   string `json:"detector_id"`
	Hash         string `json:"hash"`
	SnapshotJSON string `json:"snapshot_json"`
	LastStatus   string `json:"last_status"`
	UpdatedAt    string `json:"updated_at"`
}

var volatile = map[string]bool{"last_update_time": true, "enabled_time": true, "ui_metadata": true}

func flatten(prefix string, v any, out map[string]string) {
	switch t := v.(type) {
	case map[string]any:
		for k, x := range t {
			if volatile[k] {
				continue
			}
			p := k
			if prefix != "" {
				p = prefix + "." + k
			}
			flatten(p, x, out)
		}
	case []any:
		for i, x := range t {
			flatten(fmt.Sprintf("%s[%d]", prefix, i), x, out)
		}
	default:
		b, _ := json.Marshal(t)
		out[prefix] = string(b)
	}
}

func snap(d secanalytics.Detector) (map[string]string, string) {
	flat := map[string]string{}
	flatten("", d.Raw, flat)
	keys := make([]string, 0, len(flat))
	for k := range flat {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	h := sha256.New()
	for _, k := range keys {
		h.Write([]byte(k + "=" + flat[k] + "\n"))
	}
	return flat, hex.EncodeToString(h.Sum(nil))
}

func put(c *osclient.Client, cfg config.Config, e Entry) error {
	return c.IndexDoc(cfg.IndexName(indices.DetectorLineage), e.ChangeID, e)
}

func newEntry(det, kind, reason, author string, now time.Time) Entry {
	return Entry{DetectorID: det, ChangeID: fmt.Sprintf("%s:%d:%s", det, now.UnixNano()/1e3, kind), ChangedAt: now.UTC().Format("2006-01-02T15:04:05.000Z"),
		Reason: reason, Author: author, Kind: kind}
}

// Observe diffs each detector against its stored snapshot and records
// first-seen, definition-change and status-transition entries.
func Observe(c *osclient.Client, cfg config.Config, dets []secanalytics.Detector, sum health.Summary, now time.Time) error {
	newStatus := map[string]string{}
	for _, r := range sum.Records {
		newStatus[r.DetectorID] = r.Status
	}
	for _, d := range dets {
		flat, hash := snap(d)
		fj, _ := json.Marshal(flat)
		sidx := cfg.IndexName(indices.DetectorSnapshot)
		src, found, err := c.GetDoc(sidx, d.ID)
		if err != nil {
			return err
		}
		var old snapshot
		if found {
			_ = json.Unmarshal(src, &old)
		}
		switch {
		case !found:
			e := newEntry(d.ID, "auto-first-seen", fmt.Sprintf("Zemen first observed detector %q (type %s, watching %v).", d.Name, d.DetectorType, d.InputIndices), "zemen-auto", now)
			e.SnapshotHash = hash
			if err := put(c, cfg, e); err != nil {
				return err
			}
		case old.Hash != hash:
			var prev map[string]string
			_ = json.Unmarshal([]byte(old.SnapshotJSON), &prev)
			var changed []string
			for k, v := range flat {
				if pv, ok := prev[k]; !ok || pv != v {
					changed = append(changed, k)
				}
			}
			for k := range prev {
				if _, ok := flat[k]; !ok {
					changed = append(changed, k+" (removed)")
				}
			}
			sort.Strings(changed)
			shown := changed
			if len(shown) > 12 {
				shown = shown[:12]
			}
			e := newEntry(d.ID, "auto-definition-change", fmt.Sprintf("Detector definition changed (%d fields: %s). Nobody has recorded why yet: run 'zemen lineage add' to explain it.", len(changed), strings.Join(shown, ", ")), "zemen-auto", now)
			e.ChangedFields, e.PendingReason, e.SnapshotHash = shown, true, hash
			if err := put(c, cfg, e); err != nil {
				return err
			}
		}
		if ns, ok := newStatus[d.ID]; ok && found {
			if ps := old.LastStatus; ps != "" && ps != "unknown" && ps != ns {
				reason := fmt.Sprintf("Status changed from %s to %s.", ps, ns)
				for _, r := range sum.Records {
					if r.DetectorID == d.ID {
						reason += " " + r.StatusReason
					}
				}
				if err := put(c, cfg, newEntry(d.ID, "auto-status-change", reason, "zemen-auto", now)); err != nil {
					return err
				}
			}
		}
		st := old.LastStatus
		if ns, ok := newStatus[d.ID]; ok {
			st = ns
		}
		if err := c.IndexDoc(sidx, d.ID, snapshot{DetectorID: d.ID, Hash: hash, SnapshotJSON: string(fj), LastStatus: st, UpdatedAt: now.UTC().Format(time.RFC3339)}); err != nil {
			return err
		}
	}
	return nil
}

// Add records a human-written reason.
func Add(c *osclient.Client, cfg config.Config, detectorID, reason, trigger, author string) (Entry, error) {
	if strings.TrimSpace(reason) == "" {
		return Entry{}, fmt.Errorf("a reason is required")
	}
	if author == "" {
		author = "unknown"
	}
	e := newEntry(detectorID, "manual", reason, author, time.Now())
	e.TriggerEvent = trigger
	return e, put(c, cfg, e)
}

// RecordReplay logs regressions and recoveries between two replay runs.
func RecordReplay(c *osclient.Client, cfg config.Config, caseID string, prior, now []replay.DetectorResult) error {
	prev := map[string]replay.DetectorResult{}
	for _, p := range prior {
		prev[p.DetectorID] = p
	}
	for _, r := range now {
		p, had := prev[r.DetectorID]
		switch {
		case !r.Passed && had && p.Passed:
			e := newEntry(r.DetectorID, "auto-replay-regression", fmt.Sprintf("REGRESSION: replay case %q passed on %s but now fails: %s", caseID, p.CheckedAt, r.Error), "zemen-auto", time.Now())
			e.TriggerEvent = "replay:" + caseID
			if err := put(c, cfg, e); err != nil {
				return err
			}
		case r.Passed && had && !p.Passed:
			e := newEntry(r.DetectorID, "auto-replay-recovered", fmt.Sprintf("Replay case %q passes again (it failed on %s).", caseID, p.CheckedAt), "zemen-auto", time.Now())
			e.TriggerEvent = "replay:" + caseID
			if err := put(c, cfg, e); err != nil {
				return err
			}
		case !r.Passed && !had:
			e := newEntry(r.DetectorID, "auto-replay-failed", fmt.Sprintf("Replay case %q FAILED on its first run: %s", caseID, r.Error), "zemen-auto", time.Now())
			e.TriggerEvent = "replay:" + caseID
			if err := put(c, cfg, e); err != nil {
				return err
			}
		}
	}
	return nil
}

// ForDetector returns a detector's entries, oldest first.
func ForDetector(c *osclient.Client, cfg config.Config, detectorID string) ([]Entry, error) {
	hits, err := osclient.SearchAs[Entry](c, cfg.IndexName(indices.DetectorLineage), map[string]any{
		"size": 5000, "query": map[string]any{"term": map[string]any{"detector_id": detectorID}}})
	if err != nil {
		return nil, err
	}
	var out []Entry
	for _, h := range hits {
		if h.Source.DetectorID == detectorID { // belt and braces if the server ignores the term filter
			out = append(out, h.Source)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ChangedAt < out[j].ChangedAt })
	return out, nil
}

// Biography renders a detector's life story.
func Biography(rec health.Record, entries []Entry) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Biography of %s (%s)\n", rec.DetectorName, rec.DetectorID)
	fmt.Fprintf(&b, "Now: %s - %s\n", rec.Status, rec.StatusReason)
	if len(rec.MitreTechniques) > 0 {
		fmt.Fprintf(&b, "Claims to cover: %s\n", strings.Join(rec.MitreTechniques, ", "))
	}
	b.WriteString("\n")
	if len(entries) == 0 {
		b.WriteString("No history recorded yet. Run 'zemen sync' to start the record.\n")
	}
	for _, e := range entries {
		day := e.ChangedAt
		if len(day) >= 10 {
			day = day[:10]
		}
		fmt.Fprintf(&b, "%s  [%s] %s", day, e.Kind, e.Reason)
		if e.TriggerEvent != "" {
			fmt.Fprintf(&b, " (trigger: %s)", e.TriggerEvent)
		}
		fmt.Fprintf(&b, " - %s\n", e.Author)
	}
	return b.String()
}

// PendingReasons counts automatic definition changes nobody has explained
// since the latest one.
func PendingReasons(entries []Entry) int {
	pend := 0
	var lastAuto string
	for _, e := range entries {
		if e.Kind == "auto-definition-change" && e.PendingReason {
			lastAuto = e.ChangedAt
			pend++
		}
		if e.Kind == "manual" && lastAuto != "" && e.ChangedAt > lastAuto {
			pend = 0
		}
	}
	return pend
}
