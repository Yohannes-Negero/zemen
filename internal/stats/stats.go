// Package stats turns raw findings into per-detector time series: daily
// counts (bucketed in the configured local time zone), firing episodes,
// and robust baselines used for cadence learning and spike detection.
package stats

import (
	"math"
	"sort"
	"time"

	"zemen/internal/secanalytics"
)

// DayFmt is the day-key layout.
const DayFmt = "2006-01-02"

// DetectorStats is everything derived from one detector's findings.
type DetectorStats struct {
	DetectorID string
	Timestamps []int64        // ascending, epoch millis
	Daily      map[string]int // local day -> finding count
	FirstDay   time.Time      // civil date of the first finding
	QueryNames map[string]bool
	QueryTags  map[string]bool
}

// Build groups findings by detector.
func Build(findings []secanalytics.Finding, loc *time.Location) map[string]*DetectorStats {
	out := map[string]*DetectorStats{}
	for _, f := range findings {
		if f.DetectorID == "" || f.Timestamp <= 0 {
			continue
		}
		d := out[f.DetectorID]
		if d == nil {
			d = &DetectorStats{DetectorID: f.DetectorID, Daily: map[string]int{}, QueryNames: map[string]bool{}, QueryTags: map[string]bool{}}
			out[f.DetectorID] = d
		}
		d.Timestamps = append(d.Timestamps, f.Timestamp)
		d.Daily[DayKey(f.Timestamp, loc)]++
		for _, n := range f.QueryNames {
			d.QueryNames[n] = true
		}
		for _, t := range f.QueryTags {
			d.QueryTags[t] = true
		}
	}
	for _, d := range out {
		sort.Slice(d.Timestamps, func(i, j int) bool { return d.Timestamps[i] < d.Timestamps[j] })
		first := time.UnixMilli(d.Timestamps[0]).In(loc)
		d.FirstDay = time.Date(first.Year(), first.Month(), first.Day(), 0, 0, 0, 0, time.UTC)
	}
	return out
}

// DayKey returns the local-day key of an epoch-millis timestamp.
func DayKey(ms int64, loc *time.Location) string { return time.UnixMilli(ms).In(loc).Format(DayFmt) }

// Civil returns the local civil date (UTC midnight) of a time.
func Civil(t time.Time, loc *time.Location) time.Time {
	l := t.In(loc)
	return time.Date(l.Year(), l.Month(), l.Day(), 0, 0, 0, 0, time.UTC)
}

// Last returns the most recent finding timestamp.
func (d *DetectorStats) Last() (int64, bool) {
	if d == nil || len(d.Timestamps) == 0 {
		return 0, false
	}
	return d.Timestamps[len(d.Timestamps)-1], true
}

// EpisodeStarts clusters findings: a new episode starts when the gap to
// the previous finding exceeds gap. A burst of 500 findings in one minute
// is one episode, which is what cadence should be measured on.
func EpisodeStarts(ts []int64, gap time.Duration) []int64 {
	var starts []int64
	var prev int64
	for i, t := range ts {
		if i == 0 || time.Duration(t-prev)*time.Millisecond > gap {
			starts = append(starts, t)
		}
		prev = t
	}
	return starts
}

// GapHours returns consecutive differences between episode starts, in hours.
func GapHours(starts []int64) []float64 {
	var g []float64
	for i := 1; i < len(starts); i++ {
		g = append(g, float64(starts[i]-starts[i-1])/3.6e6)
	}
	return g
}

// Quantile returns the q-quantile (0..1) of vals (linear interpolation).
func Quantile(vals []float64, q float64) float64 {
	if len(vals) == 0 {
		return 0
	}
	s := append([]float64(nil), vals...)
	sort.Float64s(s)
	if len(s) == 1 {
		return s[0]
	}
	pos := q * float64(len(s)-1)
	lo := int(math.Floor(pos))
	hi := int(math.Ceil(pos))
	return s[lo] + (s[hi]-s[lo])*(pos-float64(lo))
}

// Baseline summarizes a detector's normal daily volume before a day.
type Baseline struct {
	Mean, Std float64
	Days      int
}

// BaselineWindowDays is how far back a baseline looks.
const BaselineWindowDays = 90

// MinBaselineDays is the history needed before spikes are judged at all.
const MinBaselineDays = 14

// BaselineBefore computes the baseline from the up-to-90 days before day,
// starting no earlier than the detector's first finding. Zero-count days
// are included: a quiet detector's normal really is mostly zeros.
func (d *DetectorStats) BaselineBefore(day time.Time) Baseline {
	start := day.AddDate(0, 0, -BaselineWindowDays)
	if start.Before(d.FirstDay) {
		start = d.FirstDay
	}
	var vals []float64
	for t := start; t.Before(day); t = t.AddDate(0, 0, 1) {
		vals = append(vals, float64(d.Daily[t.Format(DayFmt)]))
	}
	if len(vals) == 0 {
		return Baseline{}
	}
	var sum float64
	for _, v := range vals {
		sum += v
	}
	mean := sum / float64(len(vals))
	var ss float64
	for _, v := range vals {
		ss += (v - mean) * (v - mean)
	}
	return Baseline{Mean: mean, Std: math.Sqrt(ss / float64(len(vals))), Days: len(vals)}
}

// Threshold is the count above which a day is a spike.
func (b Baseline) Threshold() float64 {
	t := b.Mean + 3*b.Std
	if m := b.Mean * 2; m > t {
		t = m
	}
	if t < 5 {
		t = 5
	}
	return t
}

// IsSpike reports whether count is anomalously high given the baseline.
// Days with too little history are never judged.
func (b Baseline) IsSpike(count int) bool {
	return b.Days >= MinBaselineDays && float64(count) >= b.Threshold()
}

// SpikeDays returns every day (ascending) in [from, to] that is a spike.
func (d *DetectorStats) SpikeDays(from, to time.Time) []time.Time {
	if d == nil {
		return nil
	}
	if from.Before(d.FirstDay) {
		from = d.FirstDay
	}
	var out []time.Time
	for t := from; !t.After(to); t = t.AddDate(0, 0, 1) {
		c := d.Daily[t.Format(DayFmt)]
		if c == 0 {
			continue
		}
		if d.BaselineBefore(t).IsSpike(c) {
			out = append(out, t)
		}
	}
	return out
}
