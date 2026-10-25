// Package debt computes the Detector Debt Score (proposal section 7.3):
// "technical debt" for detections. Per detector, 0-100, from three inputs:
//
//	age      time since the detector last passed a Replay Court case
//	fp       false-positive drift (dispositions first, volume proxy second)
//	coverage ATT&CK techniques it claims but has not proven by replay
//
// score = 100 * (wAge*age + wFP*fp + wCov*coverage) / (wAge+wFP+wCov)
// with weights from ZEMEN_DEBT_WEIGHT_* (default 0.4 / 0.3 / 0.3).
package debt

import (
	"fmt"
	"sort"
	"time"

	"zemen/internal/attack"
	"zemen/internal/config"
	"zemen/internal/health"
	"zemen/internal/indices"
	"zemen/internal/osclient"
	"zemen/internal/replay"
)

// Row is one detector's debt.
type Row struct {
	DetectorID   string   `json:"detector_id"`
	DetectorName string   `json:"detector_name"`
	Debt         float64  `json:"debt_score"`
	Age          float64  `json:"age_factor"`
	FP           float64  `json:"fp_factor"`
	Coverage     float64  `json:"coverage_factor"`
	Explanation  []string `json:"explanation"`
	Counted      bool     `json:"-"`
}

// Report is the whole-SOC view.
type Report struct {
	Rows     []Row          `json:"rows"`
	SOC      float64        `json:"soc"`
	Count    int            `json:"count"`
	Change30 *float64       `json:"change30"` // percent change vs ~30 days ago
	Change90 *float64       `json:"change90"`
	History  []HistoryPoint `json:"history"`
}

// HistoryPoint is one day's aggregate score.
type HistoryPoint struct {
	Date string  `json:"date"`
	SOC  float64 `json:"debt_score"`
}

type doc struct {
	DetectorID     string   `json:"detector_id"`
	DetectorName   string   `json:"detector_name,omitempty"`
	DebtScore      float64  `json:"debt_score"`
	AgeFactor      float64  `json:"age_factor"`
	FPFactor       float64  `json:"fp_factor"`
	CoverageFactor float64  `json:"coverage_factor"`
	Explanation    []string `json:"explanation,omitempty"`
	Kind           string   `json:"kind"`
	Date           string   `json:"date,omitempty"`
	DetectorCount  int      `json:"detector_count,omitempty"`
	ComputedAt     string   `json:"computed_at"`
}

func clamp(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v > 1 {
		return 1
	}
	return v
}

// Compute scores every detector and persists current + history.
func Compute(c *osclient.Client, cfg config.Config, recs []health.Record, cases []replay.Stored, now time.Time) (Report, error) {
	var rep Report
	_, perDet := replay.VerifiedTechniques(cases, cfg.DebtVerifyDays, now)
	mapped := map[string]bool{}
	lastPass := map[string]time.Time{}
	for _, cs := range cases {
		for _, id := range cs.MappedDetectorIDs {
			mapped[id] = true
		}
		for _, r := range cs.Results {
			if t, err := time.Parse(time.RFC3339, r.LastPassAt); err == nil && t.After(lastPass[r.DetectorID]) {
				lastPass[r.DetectorID] = t
			}
		}
	}
	wA, wF, wC := cfg.DebtWeightAge, cfg.DebtWeightFP, cfg.DebtWeightCoverage
	if wA+wF+wC <= 0 {
		return rep, fmt.Errorf("debt weights must sum to more than zero")
	}
	var total float64
	for _, r := range recs {
		row := Row{DetectorID: r.DetectorID, DetectorName: r.DetectorName, Counted: r.Enabled, Explanation: []string{}}
		// age
		switch {
		case !mapped[r.DetectorID]:
			row.Age = 1
			row.Explanation = append(row.Explanation, "No Replay Court case is mapped to this detector, so nothing proves it works (age factor 1.00).")
		case lastPass[r.DetectorID].IsZero():
			row.Age = 1
			row.Explanation = append(row.Explanation, "Replay cases exist but this detector has never passed one (age factor 1.00).")
		default:
			days := now.Sub(lastPass[r.DetectorID]).Hours() / 24
			row.Age = clamp(days / 90)
			row.Explanation = append(row.Explanation, fmt.Sprintf("Last passed a replay %.0f days ago; debt accrues linearly to 1.00 at 90 days (age factor %.2f).", days, row.Age))
		}
		// false positives
		switch r.FPBasis {
		case "dispositions":
			row.FP = clamp(r.FPTrendScore)
			row.Explanation = append(row.Explanation, fmt.Sprintf("Analyst dispositions put the recent false-positive rate at %.0f%% (fp factor %.2f).", r.FPTrendScore*100, row.FP))
		case "proxy_volume":
			row.FP = clamp((r.SurgeRatio - 1) / 9)
			row.Explanation = append(row.Explanation, fmt.Sprintf("No dispositions; recent volume is %.1fx normal, a weak noise proxy (fp factor %.2f).", r.SurgeRatio, row.FP))
		default:
			row.Explanation = append(row.Explanation, "No false-positive data yet (fp factor 0.00). Record dispositions with 'zemen disposition'.")
		}
		switch r.Status {
		case health.StatusNoiseDrowned:
			row.FP = 1
			row.Explanation = append(row.Explanation, "Status is noise_drowned: fp factor forced to 1.00.")
		case health.StatusNoiseSuspected:
			if row.FP < 0.6 {
				row.FP = 0.6
				row.Explanation = append(row.Explanation, "Status is noise_suspected: fp factor raised to at least 0.60.")
			}
		}
		// coverage
		if len(r.MitreTechniques) == 0 {
			row.Coverage = 0.5
			row.Explanation = append(row.Explanation, "No ATT&CK techniques confirmed, so what it claims to cover is unknown (coverage factor 0.50). Tag it in the UI or with 'zemen tags'.")
		} else {
			parents := map[string]bool{}
			for _, t := range r.MitreTechniques {
				_, p := attack.Normalize(t)
				parents[p] = true
			}
			ver := 0
			for p := range parents {
				if t, ok := perDet[r.DetectorID][p]; ok && now.Sub(t) <= time.Duration(cfg.DebtVerifyDays)*24*time.Hour {
					ver++
				}
			}
			row.Coverage = clamp(float64(len(parents)-ver) / float64(len(parents)))
			row.Explanation = append(row.Explanation, fmt.Sprintf("Claims %d technique(s); %d verified by a passing replay in the last %d days (coverage factor %.2f).", len(parents), ver, cfg.DebtVerifyDays, row.Coverage))
		}
		row.Debt = round1(100 * (wA*row.Age + wF*row.FP + wC*row.Coverage) / (wA + wF + wC))
		if row.Counted {
			total += row.Debt
			rep.Count++
		}
		rep.Rows = append(rep.Rows, row)
	}
	if rep.Count > 0 {
		rep.SOC = round1(total / float64(rep.Count))
	}
	sort.Slice(rep.Rows, func(i, j int) bool { return rep.Rows[i].Debt > rep.Rows[j].Debt })

	// Persist + history.
	idx := cfg.IndexName(indices.DetectorDebt)
	ts := now.UTC().Format(time.RFC3339)
	var items []osclient.BulkItem
	for _, r := range rep.Rows {
		items = append(items, osclient.BulkItem{Action: "index", Index: idx, ID: r.DetectorID, Doc: doc{
			DetectorID: r.DetectorID, DetectorName: r.DetectorName, DebtScore: r.Debt, AgeFactor: r.Age, FPFactor: r.FP,
			CoverageFactor: r.Coverage, Explanation: r.Explanation, Kind: "current", ComputedAt: ts}})
	}
	day := now.UTC().Format("2006-01-02")
	items = append(items,
		osclient.BulkItem{Action: "index", Index: idx, ID: "__SOC__", Doc: doc{DetectorID: "__SOC__", DebtScore: rep.SOC, Kind: "soc-current", DetectorCount: rep.Count, ComputedAt: ts}},
		osclient.BulkItem{Action: "index", Index: idx, ID: "__SOC__:" + day, Doc: doc{DetectorID: "__SOC__", DebtScore: rep.SOC, Kind: "soc-history", Date: day, DetectorCount: rep.Count, ComputedAt: ts}})
	if fails, err := c.Bulk(items, true); err != nil {
		return rep, fmt.Errorf("writing debt: %w", err)
	} else if len(fails) > 0 {
		return rep, fmt.Errorf("debt write failed: %s", fails[0])
	}

	hs, err := osclient.AllDocs[doc](c, idx)
	if err != nil {
		return rep, err
	}
	for _, h := range hs {
		if h.Source.Kind == "soc-history" {
			rep.History = append(rep.History, HistoryPoint{Date: h.Source.Date, SOC: h.Source.DebtScore})
		}
	}
	sort.Slice(rep.History, func(i, j int) bool { return rep.History[i].Date < rep.History[j].Date })
	rep.Change30 = change(rep.History, day, 30, rep.SOC)
	rep.Change90 = change(rep.History, day, 90, rep.SOC)
	return rep, nil
}

// change compares today's score with the latest history point at least
// `days` old; nil if no such point exists yet.
func change(h []HistoryPoint, today string, days int, cur float64) *float64 {
	t, err := time.Parse("2006-01-02", today)
	if err != nil {
		return nil
	}
	cut := t.AddDate(0, 0, -days).Format("2006-01-02")
	var ref *HistoryPoint
	for i := range h {
		if h[i].Date <= cut {
			ref = &h[i]
		}
	}
	if ref == nil || ref.SOC == 0 {
		return nil
	}
	v := round1((cur - ref.SOC) / ref.SOC * 100)
	return &v
}

func round1(v float64) float64 { return float64(int(v*10+0.5)) / 10 }

// Load reads the stored debt rows and history without recomputing.
func Load(c *osclient.Client, cfg config.Config) (Report, error) {
	var rep Report
	hs, err := osclient.AllDocs[doc](c, cfg.IndexName(indices.DetectorDebt))
	if err != nil {
		return rep, err
	}
	var today string
	for _, h := range hs {
		d := h.Source
		switch d.Kind {
		case "current":
			rep.Rows = append(rep.Rows, Row{DetectorID: d.DetectorID, DetectorName: d.DetectorName, Debt: d.DebtScore, Age: d.AgeFactor,
				FP: d.FPFactor, Coverage: d.CoverageFactor, Explanation: d.Explanation})
		case "soc-current":
			rep.SOC, rep.Count = d.DebtScore, d.DetectorCount
			if len(d.ComputedAt) >= 10 {
				today = d.ComputedAt[:10]
			}
		case "soc-history":
			rep.History = append(rep.History, HistoryPoint{Date: d.Date, SOC: d.DebtScore})
		}
	}
	sort.Slice(rep.Rows, func(i, j int) bool { return rep.Rows[i].Debt > rep.Rows[j].Debt })
	sort.Slice(rep.History, func(i, j int) bool { return rep.History[i].Date < rep.History[j].Date })
	if today != "" {
		rep.Change30 = change(rep.History, today, 30, rep.SOC)
		rep.Change90 = change(rep.History, today, 90, rep.SOC)
	}
	return rep, nil
}
