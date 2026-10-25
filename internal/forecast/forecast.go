// Package forecast is Seasonal Risk Forecasting (proposal section 7.4):
// the Temporal Context Engine run forward. It lists upcoming calendar and
// learned windows, estimates from local history how each detector's
// volume will move, and recommends threshold/staffing changes BEFORE the
// noise arrives. A webhook notification fires once per window.
package forecast

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"time"

	"zemen/internal/config"
	"zemen/internal/health"
	"zemen/internal/indices"
	"zemen/internal/osclient"
	"zemen/internal/stats"
	"zemen/internal/temporal"
)

// Reco is one detector-level recommendation.
type Reco struct {
	DetectorID   string  `json:"detector_id"`
	DetectorName string  `json:"detector_name"`
	Multiplier   float64 `json:"multiplier"`
	Occurrences  int     `json:"occurrences"`
	Text         string  `json:"text"`
}

// Item is one upcoming window.
type Item struct {
	SignalID        string `json:"signal_id"`
	Name            string `json:"name"`
	Start           string `json:"start"`
	End             string `json:"end"`
	DaysUntil       int    `json:"days_until"`
	Effect          string `json:"effect"`
	Source          string `json:"source"`
	Approximate     bool   `json:"approximate"`
	Summary         string `json:"summary"`
	Recommendations []Reco `json:"recommendations"`
	AlertedAt       string `json:"alerted_at,omitempty"`
	id              string
}

type doc struct {
	SignalID            string `json:"signal_id"`
	Name                string `json:"name"`
	Start               string `json:"start"`
	End                 string `json:"end"`
	DaysUntil           int    `json:"days_until"`
	Effect              string `json:"effect"`
	Summary             string `json:"summary"`
	RecommendationsJSON string `json:"recommendations_json"`
	AlertedAt           string `json:"alerted_at,omitempty"`
	UpdatedAt           string `json:"updated_at"`
}

// Compute builds the forecast for the configured horizon and persists it.
func Compute(c *osclient.Client, cfg config.Config, res *temporal.Result, recs []health.Record, now time.Time) ([]Item, error) {
	today := res.Today
	horizon := today.AddDate(0, 0, cfg.ForecastHorizonDays)
	idx := cfg.IndexName(indices.Forecast)
	prevAlert := map[string]string{}
	if hs, err := osclient.AllDocs[doc](c, idx); err == nil {
		for _, h := range hs {
			prevAlert[h.ID] = h.Source.AlertedAt
		}
	}
	names := map[string]string{}
	enabled := map[string]bool{}
	for _, r := range recs {
		names[r.DetectorID] = r.DetectorName
		enabled[r.DetectorID] = r.Enabled
	}

	var items []Item
	overlaySeen := map[string]int{}
	for _, o := range res.Occurrences {
		if o.End.Before(today) || o.Start.After(horizon) {
			continue
		}
		it := Item{SignalID: o.SignalID, Name: o.Name, Start: o.Start.Format(stats.DayFmt), End: o.End.Format(stats.DayFmt),
			Effect: o.Effect, Source: o.Source, Approximate: o.Approximate, id: o.SignalID + ":" + o.Start.Format(stats.DayFmt),
			Recommendations: []Reco{}}
		it.DaysUntil = daysUntil(today, o.Start)
		dets := make([]string, 0, len(res.Stats))
		for det := range res.Stats {
			dets = append(dets, det)
		}
		sort.Strings(dets)
		for _, det := range dets {
			if !enabled[det] {
				continue
			}
			if r, ok := reco(det, names[det], res.Stats[det][o.SignalID], it.Start, it.End); ok {
				it.Recommendations = append(it.Recommendations, r)
			}
		}
		items = append(items, finish(it, o.Prior, o.Notes))
	}
	for _, o := range res.Overlays {
		if o.End.Before(today) || o.Start.After(horizon) {
			continue
		}
		k := o.DetectorID + o.SignalID
		if overlaySeen[k] >= 2 { // only the next couple of occurrences per learned pattern
			continue
		}
		overlaySeen[k]++
		it := Item{SignalID: o.SignalID, Name: o.Name, Start: o.Start.Format(stats.DayFmt), End: o.End.Format(stats.DayFmt),
			Effect: o.Effect, Source: o.Source, id: o.SignalID + ":" + o.DetectorID + ":" + o.Start.Format(stats.DayFmt),
			Recommendations: []Reco{}}
		it.DaysUntil = daysUntil(today, o.Start)
		if r, ok := reco(o.DetectorID, names[o.DetectorID], res.Stats[o.DetectorID][o.SignalID], it.Start, it.End); ok {
			it.Recommendations = append(it.Recommendations, r)
		}
		items = append(items, finish(it, o.Prior, o.Notes))
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].Start != items[j].Start {
			return items[i].Start < items[j].Start
		}
		return items[i].id < items[j].id
	})

	var bulk []osclient.BulkItem
	ts := now.UTC().Format(time.RFC3339)
	for i := range items {
		items[i].AlertedAt = prevAlert[items[i].id]
		rb, _ := json.Marshal(items[i].Recommendations)
		bulk = append(bulk, osclient.BulkItem{Action: "index", Index: idx, ID: items[i].id, Doc: doc{
			SignalID: items[i].SignalID, Name: items[i].Name, Start: items[i].Start, End: items[i].End, DaysUntil: items[i].DaysUntil,
			Effect: items[i].Effect, Summary: items[i].Summary, RecommendationsJSON: string(rb), AlertedAt: items[i].AlertedAt, UpdatedAt: ts}})
	}
	if fails, err := c.Bulk(bulk, true); err != nil {
		return items, fmt.Errorf("writing forecast: %w", err)
	} else if len(fails) > 0 {
		return items, fmt.Errorf("forecast write failed: %s", fails[0])
	}
	return items, nil
}

func daysUntil(today, start time.Time) int {
	d := int(start.Sub(today).Hours() / 24)
	if d < 0 {
		return 0 // already under way
	}
	return d
}

func reco(det, name string, s temporal.SigStat, start, end string) (Reco, bool) {
	mult, n := s.Multiplier()
	if n == 0 {
		return Reco{}, false
	}
	r := Reco{DetectorID: det, DetectorName: name, Multiplier: round1(mult), Occurrences: n}
	switch {
	case mult >= 1.5:
		r.Text = fmt.Sprintf("Expect about %.1fx normal findings from %q (seen across %d earlier occurrence(s)). Consider raising its alert threshold or widening its suppression window by a similar factor for %s to %s, and pre-tag the burst as expected.", mult, name, n, start, end)
	case mult <= 0.6:
		r.Text = fmt.Sprintf("Expect %q to be quieter than normal (about %.1fx, across %d earlier occurrence(s)). Do not read a quiet %s to %s as a silent detector.", name, mult, n, start, end)
	default:
		return Reco{}, false
	}
	return r, true
}

func finish(it Item, prior float64, notes string) Item {
	spikes := 0
	for _, r := range it.Recommendations {
		if r.Multiplier >= 2 {
			spikes++
		}
	}
	switch {
	case len(it.Recommendations) == 0:
		it.Summary = fmt.Sprintf("%s starts in %d day(s). No detector has local history for this window yet (prior confidence %.2f), so no adjustment is recommended; Zemen will learn from this occurrence.", it.Name, it.DaysUntil, prior)
	case spikes >= 2:
		it.Summary = fmt.Sprintf("%s starts in %d day(s): %d detectors are expected to run at 2x normal or more. Plan extra analyst coverage and adjust thresholds beforehand.", it.Name, it.DaysUntil, spikes)
	default:
		it.Summary = fmt.Sprintf("%s starts in %d day(s): %d detector(s) have a learned volume change. See recommendations.", it.Name, it.DaysUntil, len(it.Recommendations))
	}
	if notes != "" {
		it.Summary += " Note: " + notes
	}
	return it
}

func round1(v float64) float64 { return float64(int(v*10+0.5)) / 10 }

// Notify sends one webhook per window that enters the lead time and marks
// it alerted. Returns how many notifications were sent.
func Notify(c *osclient.Client, cfg config.Config, items []Item, now time.Time) (int, error) {
	if cfg.WebhookURL == "" {
		return 0, nil
	}
	idx := cfg.IndexName(indices.Forecast)
	sent := 0
	for _, it := range items {
		if it.AlertedAt != "" || it.DaysUntil > cfg.ForecastLeadDays {
			continue
		}
		body, _ := json.Marshal(map[string]any{
			"text": fmt.Sprintf("[Zemen] %s (%s to %s): %s", it.Name, it.Start, it.End, it.Summary), "forecast": it})
		resp, err := http.Post(cfg.WebhookURL, "application/json", bytes.NewReader(body))
		if err != nil {
			return sent, fmt.Errorf("webhook: %w", err)
		}
		resp.Body.Close()
		if resp.StatusCode >= 300 {
			return sent, fmt.Errorf("webhook returned HTTP %d", resp.StatusCode)
		}
		rb, _ := json.Marshal(it.Recommendations)
		if err := c.IndexDoc(idx, it.id, doc{SignalID: it.SignalID, Name: it.Name, Start: it.Start, End: it.End, DaysUntil: it.DaysUntil,
			Effect: it.Effect, Summary: it.Summary, RecommendationsJSON: string(rb), AlertedAt: now.UTC().Format(time.RFC3339), UpdatedAt: now.UTC().Format(time.RFC3339)}); err != nil {
			return sent, err
		}
		sent++
	}
	return sent, nil
}

// Load reads the stored forecast, soonest first.
func Load(c *osclient.Client, cfg config.Config) ([]Item, error) {
	hs, err := osclient.AllDocs[doc](c, cfg.IndexName(indices.Forecast))
	if err != nil {
		return nil, err
	}
	var out []Item
	for _, h := range hs {
		d := h.Source
		it := Item{SignalID: d.SignalID, Name: d.Name, Start: d.Start, End: d.End, DaysUntil: d.DaysUntil, Effect: d.Effect,
			Summary: d.Summary, AlertedAt: d.AlertedAt, id: h.ID, Recommendations: []Reco{}}
		_ = json.Unmarshal([]byte(d.RecommendationsJSON), &it.Recommendations)
		out = append(out, it)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Start < out[j].Start })
	return out, nil
}
