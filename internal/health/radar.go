// Package health is the Detector Health Radar (proposal module 1): per
// detector it learns an expected firing cadence, flags silent detectors,
// tracks false-positive drift (explicit analyst dispositions first, a
// calendar-aware volume proxy otherwise), and suggests ATT&CK tags.
package health

import (
	"fmt"
	"sort"
	"time"

	"zemen/internal/attack"
	"zemen/internal/config"
	"zemen/internal/indices"
	"zemen/internal/osclient"
	"zemen/internal/secanalytics"
	"zemen/internal/stats"
)

// Status values.
const (
	StatusHealthy        = "healthy"
	StatusSilent         = "silent"            // has fired before, quiet beyond its learned threshold
	StatusNoiseDrowned   = "noise_drowned"     // explicit dispositions show most findings are false positives
	StatusNoiseSuspected = "noise_suspected"   // volume/triage proxy suggests noise; no explicit dispositions
	StatusNeverFired     = "never_fired"       // CONFIRMED: complete findings history has zero findings
	StatusNoDataInWindow = "no_data_in_window" // history was truncated; cannot tell
	StatusDisabled       = "disabled"
)

// Record is the detector_health document (proposal section 8.1 plus
// supporting fields).
type Record struct {
	DetectorID           string   `json:"detector_id"`
	DetectorName         string   `json:"detector_name"`
	DetectorType         string   `json:"detector_type"`
	Enabled              bool     `json:"enabled"`
	InputIndices         []string `json:"input_indices"`
	LastFiredAt          *string  `json:"last_fired_at,omitempty"`
	ExpectedCadenceHours float64  `json:"expected_cadence_hours"`
	SilenceThresholdHrs  float64  `json:"silence_threshold_hours"`
	HistoryEpisodes      int      `json:"history_episodes"`
	CadenceBasis         string   `json:"cadence_basis"`
	Status               string   `json:"status"`
	StatusReason         string   `json:"status_reason"`
	FPTrendScore         float64  `json:"fp_trend_score"`
	FPDrift              float64  `json:"fp_drift"`
	FPBasis              string   `json:"fp_basis"`
	FindingsTotal        int      `json:"findings_total"`
	Findings7d           int      `json:"findings_7d"`
	BaselinePerDay       float64  `json:"baseline_per_day"`
	SurgeRatio           float64  `json:"surge_ratio"`
	MitreTechniques      []string `json:"mitre_techniques"`
	SuggestedTechniques  []string `json:"suggested_techniques"`
	SuggestionReasons    []string `json:"suggestion_reasons"`
	WindowComplete       bool     `json:"window_complete"`
	CreatedAt            string   `json:"created_at"`
	UpdatedAt            string   `json:"updated_at"`
}

// Explainer lets the health pass ask the temporal engine whether a spike
// day was explained by the calendar.
type Explainer interface {
	IsExplainedSpike(detectorID, day string) bool
}

// Params bundles one health computation's inputs.
type Params struct {
	Client    *osclient.Client
	Cfg       config.Config
	Now       time.Time
	Detectors []secanalytics.Detector
	Findings  secanalytics.FindingsResult
	Stats     map[string]*stats.DetectorStats
	Explain   Explainer
	Matrix    *attack.Matrix
}

// Summary is the outcome of a health computation.
type Summary struct {
	Records    []Record
	Counts     map[string]int
	PrevStatus map[string]string // status before this run
	Errors     []error
}

type disposition struct {
	FindingID  string `json:"finding_id"`
	DetectorID string `json:"detector_id"`
	Verdict    string `json:"verdict"`
	At         string `json:"at"`
}

// Compute evaluates every detector and persists the records.
func Compute(p Params) (Summary, error) {
	loc := p.Cfg.Location()
	today := stats.Civil(p.Now, loc)
	idx := p.Cfg.IndexName(indices.DetectorHealth)
	sum := Summary{Counts: map[string]int{}, PrevStatus: map[string]string{}}

	existing := map[string]Record{}
	hits, err := osclient.AllDocs[Record](p.Client, idx)
	if err != nil {
		return sum, fmt.Errorf("reading existing health records: %w", err)
	}
	for _, h := range hits {
		existing[h.ID] = h.Source
		sum.PrevStatus[h.ID] = h.Source.Status
	}

	dh, err := osclient.AllDocs[disposition](p.Client, p.Cfg.IndexName(indices.Disposition))
	if err != nil {
		return sum, fmt.Errorf("reading dispositions: %w", err)
	}
	disp := map[string][]disposition{}
	for _, h := range dh {
		disp[h.Source.DetectorID] = append(disp[h.Source.DetectorID], h.Source)
	}

	nowS := p.Now.UTC().Format(time.RFC3339)
	var items []osclient.BulkItem
	for _, d := range p.Detectors {
		s := p.Stats[d.ID]
		rec := Record{
			DetectorID: d.ID, DetectorName: d.Name, DetectorType: d.DetectorType, Enabled: d.Enabled,
			InputIndices: nonNil(d.InputIndices), WindowComplete: p.Findings.DetectorComplete(d.ID), UpdatedAt: nowS,
			MitreTechniques: []string{}, SuggestedTechniques: []string{}, SuggestionReasons: []string{},
		}
		if old, ok := existing[d.ID]; ok {
			rec.CreatedAt = old.CreatedAt
			rec.MitreTechniques = nonNil(old.MitreTechniques)
		}
		if rec.CreatedAt == "" {
			rec.CreatedAt = nowS
		}

		var last int64
		var have bool
		if s != nil {
			rec.FindingsTotal = len(s.Timestamps)
			last, have = s.Last()
			if have {
				t := time.UnixMilli(last).UTC().Format(time.RFC3339)
				rec.LastFiredAt = &t
			}
			rec.ExpectedCadenceHours, rec.SilenceThresholdHrs, rec.HistoryEpisodes, rec.CadenceBasis = cadence(s, p.Cfg.DefaultSilence)
		} else {
			rec.SilenceThresholdHrs = p.Cfg.DefaultSilence.Hours()
			rec.CadenceBasis = "none"
		}

		noise, noiseReason := noiseSignals(&rec, s, disp[d.ID], today, p)

		switch {
		case !d.Enabled:
			rec.Status, rec.StatusReason = StatusDisabled, "Detector is disabled in Security Analytics."
		case !have && p.Findings.DetectorComplete(d.ID):
			rec.Status, rec.StatusReason = StatusNeverFired, "The complete findings history contains no finding for this detector."
		case !have:
			rec.Status, rec.StatusReason = StatusNoDataInWindow, fmt.Sprintf("Only %d of %d findings could be fetched and none belong to this detector; it may have fired earlier or never. Not guessing.", len(p.Findings.Findings), p.Findings.Total)
		default:
			ago := p.Now.Sub(time.UnixMilli(last))
			switch {
			case ago.Hours() > rec.SilenceThresholdHrs:
				rec.Status = StatusSilent
				rec.StatusReason = fmt.Sprintf("Last fired %.1f days ago; its silence threshold is %.1f days (%s cadence, %d episodes).", ago.Hours()/24, rec.SilenceThresholdHrs/24, rec.CadenceBasis, rec.HistoryEpisodes)
			case noise == StatusNoiseDrowned:
				rec.Status, rec.StatusReason = StatusNoiseDrowned, noiseReason
			case noise == StatusNoiseSuspected:
				rec.Status, rec.StatusReason = StatusNoiseSuspected, noiseReason
			default:
				rec.Status = StatusHealthy
				rec.StatusReason = fmt.Sprintf("Fired %.1f hours ago, within its %.1f-day silence threshold.", ago.Hours(), rec.SilenceThresholdHrs/24)
			}
		}

		// ATT&CK suggestions (never auto-applied).
		if p.Matrix != nil {
			texts := []string{d.Name, d.DetectorType}
			var tags []string
			if s != nil {
				var names []string
				for n := range s.QueryNames {
					names = append(names, n)
				}
				sort.Strings(names)
				texts = append(texts, names...)
				for t := range s.QueryTags {
					tags = append(tags, t)
				}
				sort.Strings(tags)
			}
			confirmed := map[string]bool{}
			for _, t := range rec.MitreTechniques {
				_, par := attack.Normalize(t)
				confirmed[par] = true
			}
			for _, sg := range attack.Suggest(p.Matrix, texts, tags) {
				if _, par := attack.Normalize(sg.Technique); confirmed[par] {
					continue
				}
				rec.SuggestedTechniques = append(rec.SuggestedTechniques, sg.Technique)
				rec.SuggestionReasons = append(rec.SuggestionReasons, sg.Technique+": "+sg.Reason)
			}
		}

		sum.Counts[rec.Status]++
		sum.Records = append(sum.Records, rec)
		items = append(items, osclient.BulkItem{Action: "index", Index: idx, ID: d.ID, Doc: rec})
	}
	fails, err := p.Client.Bulk(items, true)
	if err != nil {
		return sum, fmt.Errorf("writing health records: %w", err)
	}
	for _, f := range fails {
		sum.Errors = append(sum.Errors, fmt.Errorf("health write failed: %s", f))
	}
	return sum, nil
}

// cadence learns how often a detector normally fires. Findings within 60
// minutes belong to one episode; the silence threshold is 3x the 90th
// percentile gap between episodes, bounded to [6h, 90d]. With fewer than 6
// episodes there is not enough history to learn, so the configured
// default is used and the basis says so.
func cadence(s *stats.DetectorStats, def time.Duration) (medianHrs, thresholdHrs float64, episodes int, basis string) {
	starts := stats.EpisodeStarts(s.Timestamps, 60*time.Minute)
	episodes = len(starts)
	if episodes < 6 {
		return 0, def.Hours(), episodes, "default_insufficient_history"
	}
	gaps := stats.GapHours(starts)
	medianHrs = stats.Quantile(gaps, 0.5)
	thr := 3 * stats.Quantile(gaps, 0.9)
	if thr < 6 {
		thr = 6
	}
	if thr > 90*24 {
		thr = 90 * 24
	}
	return round1(medianHrs), round1(thr), episodes, "learned"
}

func round1(v float64) float64 { return float64(int(v*10+0.5)) / 10 }

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// noiseSignals fills FP/volume fields and returns a noise verdict.
func noiseSignals(rec *Record, s *stats.DetectorStats, ds []disposition, today time.Time, p Params) (string, string) {
	rec.FPBasis = "none"
	// 1. Explicit analyst dispositions beat any proxy.
	cut14, cut28 := p.Now.AddDate(0, 0, -14), p.Now.AddDate(0, 0, -28)
	var rTot, rFP, pTot, pFP int
	for _, d := range ds {
		t, err := time.Parse(time.RFC3339, d.At)
		if err != nil || t.Before(cut28) {
			continue
		}
		if t.After(cut14) {
			rTot++
			if d.Verdict == "fp" {
				rFP++
			}
		} else {
			pTot++
			if d.Verdict == "fp" {
				pFP++
			}
		}
	}
	if rTot+pTot >= 10 {
		rec.FPBasis = "dispositions"
		recent := ratio(rFP, rTot)
		prev := ratio(pFP, pTot)
		rec.FPTrendScore = round2(recent)
		rec.FPDrift = round2(recent - prev)
		if rTot >= 5 && recent >= 0.7 {
			return StatusNoiseDrowned, fmt.Sprintf("Analysts marked %d of %d recent findings (last 14 days) as false positives (%.0f%%); previous period %.0f%%.", rFP, rTot, recent*100, prev*100)
		}
		return "", ""
	}
	if s == nil {
		return "", ""
	}
	// 2. Volume proxy: recent 7 days vs the 8 weeks before, ignoring
	// spikes the calendar explains.
	recentFrom := today.AddDate(0, 0, -6)
	var recent7 int
	for t := recentFrom; !t.After(today); t = t.AddDate(0, 0, 1) {
		recent7 += s.Daily[t.Format(stats.DayFmt)]
	}
	rec.Findings7d = recent7
	baseFrom, baseTo := today.AddDate(0, 0, -63), today.AddDate(0, 0, -7)
	if baseFrom.Before(s.FirstDay) {
		baseFrom = s.FirstDay
	}
	var bsum, bn float64
	for t := baseFrom; !t.After(baseTo); t = t.AddDate(0, 0, 1) {
		bsum += float64(s.Daily[t.Format(stats.DayFmt)])
		bn++
	}
	if bn < stats.MinBaselineDays {
		return "", ""
	}
	rec.BaselinePerDay = round2(bsum / bn)
	den := bsum / bn
	if den < 0.5 {
		den = 0.5
	}
	rec.SurgeRatio = round2(float64(recent7) / 7 / den)
	rec.FPBasis = "proxy_volume"
	rec.FPTrendScore = round2(minf(1, rec.SurgeRatio/10))
	unexplained := 0
	for t := recentFrom; !t.After(today); t = t.AddDate(0, 0, 1) {
		k := t.Format(stats.DayFmt)
		c := s.Daily[k]
		if c > 0 && s.BaselineBefore(t).IsSpike(c) && !(p.Explain != nil && p.Explain.IsExplainedSpike(rec.DetectorID, k)) {
			unexplained++
		}
	}
	if unexplained >= 3 && rec.SurgeRatio >= 3 {
		return StatusNoiseSuspected, fmt.Sprintf("Volume is %.1fx its normal for %d of the last 7 days with no calendar explanation. No analyst dispositions exist, so this is a proxy; mark findings with 'zemen disposition' to confirm.", rec.SurgeRatio, unexplained)
	}
	// 3. Triage proxy from alerts, only if nothing else fired.
	if al, err := secanalytics.ListAlerts(p.Client, rec.DetectorID, 200); err == nil && len(al) >= 30 {
		fast := 0
		for _, a := range al {
			if a.AcknowledgedMil > 0 && a.StartMillis > 0 && a.AcknowledgedMil-a.StartMillis < 60_000 {
				fast++
			}
		}
		if float64(fast)/float64(len(al)) >= 0.8 {
			return StatusNoiseSuspected, fmt.Sprintf("%d of %d alerts were acknowledged within a minute, which looks like bulk dismissal rather than triage.", fast, len(al))
		}
	}
	return "", ""
}

func ratio(a, b int) float64 {
	if b == 0 {
		return 0
	}
	return float64(a) / float64(b)
}
func round2(v float64) float64 { return float64(int(v*100+0.5)) / 100 }
func minf(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}
