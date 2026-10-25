// Package temporal is the Temporal Context Engine (proposal module 2).
//
// For every detector it finds days whose finding volume is anomalously
// high, then asks: is this explained by Ethiopian calendar reality (a
// holiday, fasting season, pay window) or by a pattern this organization
// has learned about itself? Every answer carries a reasoning chain, and
// analyst feedback changes future confidence.
package temporal

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"zemen/internal/config"
	"zemen/internal/ethcal"
	"zemen/internal/federated"
	"zemen/internal/indices"
	"zemen/internal/osclient"
	"zemen/internal/secanalytics"
	"zemen/internal/stats"
)

// Labels written to finding-context.
const (
	LabelExpectedLocal = "expected_local_pattern"
	LabelExpectedOrg   = "expected_org_pattern"
	LabelUnexplained   = "unexplained_escalate"
)

// Context is the labeled explanation for one detector on one day.
type Context struct {
	DetectorID     string   `json:"detector_id"`
	DetectorName   string   `json:"detector_name"`
	Date           string   `json:"date"`
	EthiopianDate  string   `json:"ethiopian_date"`
	Count          int      `json:"count"`
	BaselineMean   float64  `json:"baseline_mean"`
	BaselineStd    float64  `json:"baseline_std"`
	Threshold      float64  `json:"threshold"`
	Ratio          float64  `json:"ratio"`
	BaselineDays   int      `json:"baseline_days"`
	Label          string   `json:"label"`
	AutoLabel      string   `json:"auto_label"`
	MatchedSignals []string `json:"matched_signals"`
	Confidence     float64  `json:"confidence"`
	Reasoning      []string `json:"reasoning"`
	Feedback       string   `json:"feedback,omitempty"`
	FeedbackNote   string   `json:"feedback_note,omitempty"`
	FeedbackSignal string   `json:"feedback_signal,omitempty"`
	FeedbackAt     string   `json:"feedback_at,omitempty"`
	UpdatedAt      string   `json:"updated_at"`
}

// SigStat is the evidence for one (detector, signal) pair.
type SigStat struct {
	Hits, Trials, Confirms, Overrides int
	MultSum                           float64
	MultN                             int
}

// Multiplier returns the mean historical volume multiplier in a signal's window.
func (s SigStat) Multiplier() (float64, int) {
	if s.MultN == 0 {
		return 0, 0
	}
	return s.MultSum / float64(s.MultN), s.MultN
}

// Result is everything one engine run produced.
type Result struct {
	Loc         *time.Location
	Today       time.Time
	Occurrences []ethcal.Occurrence // built-in + custom
	Overlays    []ethcal.Occurrence // learned, per detector
	Contexts    []Context
	Stats       map[string]map[string]SigStat // detector -> signal -> stat
	FedNotes    map[string]string
	explained   map[string]map[string]bool
}

// IsExplainedSpike reports whether the detector's spike on day was
// explained by a calendar/overlay signal (after analyst feedback).
func (r *Result) IsExplainedSpike(detectorID, day string) bool {
	return r != nil && r.explained[detectorID][day]
}

// Engine runs the temporal pass.
type Engine struct {
	Client *osclient.Client
	Cfg    config.Config
	Now    time.Time
}

type fbDoc struct {
	DetectorID string `json:"detector_id"`
	SignalID   string `json:"signal_id"`
	Confirms   int    `json:"confirms"`
	Overrides  int    `json:"overrides"`
	UpdatedAt  string `json:"updated_at"`
}

type occDoc struct {
	SignalID   string         `json:"signal_id"`
	Name       string         `json:"name"`
	DateRange  map[string]any `json:"date_range,omitempty"`
	Effect     string         `json:"expected_effect,omitempty"`
	Scope      string         `json:"affected_scope,omitempty"`
	Confidence float64        `json:"confidence"`
	Recurring  bool           `json:"recurring"`
	Notes      string         `json:"notes,omitempty"`
	Kind       string         `json:"kind"`
	Source     string         `json:"source,omitempty"`
	DetectorID string         `json:"detector_id,omitempty"`
	Hits       int            `json:"hits,omitempty"`
	Trials     int            `json:"trials,omitempty"`
	Confirms   int            `json:"confirms,omitempty"`
	Overrides  int            `json:"overrides,omitempty"`
	Approx     bool           `json:"approximate,omitempty"`
	UpdatedAt  string         `json:"updated_at"`
}

// confidence blends the signal's prior with local evidence:
// (hits + 2*prior + confirms) / (trials + 2 + confirms + overrides).
func confidence(prior float64, s SigStat) float64 {
	return (float64(s.Hits) + 2*prior + float64(s.Confirms)) / (float64(s.Trials) + 2 + float64(s.Confirms) + float64(s.Overrides))
}

func ctxID(det, day string) string { return det + ":" + day }

func fbKey(det, sig string) string { return det + "|" + sig }

// Run performs the full temporal pass and persists its outputs.
func (e *Engine) Run(detectors []secanalytics.Detector, st map[string]*stats.DetectorStats) (*Result, error) {
	loc := e.Cfg.Location()
	today := stats.Civil(e.Now, loc)
	custom, err := ethcal.LoadCustom(e.Cfg.DataDir)
	if err != nil {
		return nil, err
	}
	if errs := custom.Validate(); len(errs) > 0 {
		return nil, fmt.Errorf("calendar_custom.json problems:\n  %s", strings.Join(errs, "\n  "))
	}
	fed := federated.LoadModel(e.Cfg.DataDir)

	firstYear := today.Year() - 1
	for _, s := range st {
		if y := s.FirstDay.Year() - 1; y < firstYear {
			firstYear = y
		}
	}
	occs := ethcal.Generate(firstYear, today.Year()+1, custom)
	fedNotes := map[string]string{}
	for i := range occs {
		p, note := fed.Prior(occs[i].SignalID, occs[i].Prior)
		occs[i].Prior = p
		if note != "" {
			fedNotes[occs[i].SignalID] = note
		}
	}

	// Feedback + existing contexts (to retain analyst decisions).
	fbHits, err := osclient.AllDocs[fbDoc](e.Client, e.Cfg.IndexName(indices.Feedback))
	if err != nil {
		return nil, fmt.Errorf("reading feedback: %w", err)
	}
	fb := map[string]fbDoc{}
	for _, h := range fbHits {
		fb[fbKey(h.Source.DetectorID, h.Source.SignalID)] = h.Source
	}
	oldHits, err := osclient.AllDocs[Context](e.Client, e.Cfg.IndexName(indices.FindingContext))
	if err != nil {
		return nil, fmt.Errorf("reading existing contexts: %w", err)
	}
	old := map[string]Context{}
	for _, h := range oldHits {
		old[h.ID] = h.Source
	}

	res := &Result{Loc: loc, Today: today, Occurrences: occs, Stats: map[string]map[string]SigStat{}, FedNotes: fedNotes,
		explained: map[string]map[string]bool{}}

	byID := map[string]secanalytics.Detector{}
	for _, d := range detectors {
		byID[d.ID] = d
	}
	windowStart := today.AddDate(0, 0, -e.Cfg.LabelWindowDays)
	now := e.Now.UTC().Format(time.RFC3339)
	var ctxOut []Context

	ids := make([]string, 0, len(st))
	for id := range st {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	for _, id := range ids {
		s := st[id]
		det := byID[id] // zero value if detector was deleted; still label history
		name := det.Name
		if name == "" {
			name = id
		}
		valid := s.FirstDay.AddDate(0, 0, stats.MinBaselineDays)
		spikeList := s.SpikeDays(s.FirstDay, today)
		spikes := map[string]bool{}
		for _, d := range spikeList {
			spikes[d.Format(stats.DayFmt)] = true
		}
		ss := map[string]SigStat{}

		// Evidence for built-in/custom signals from completed occurrences.
		for _, o := range occs {
			if o.Start.Before(valid) || o.End.After(today) {
				continue
			}
			cur := ss[o.SignalID]
			cur.Trials++
			var sum float64
			n := 0
			hit := false
			for t := o.Start; !t.After(o.End); t = t.AddDate(0, 0, 1) {
				k := t.Format(stats.DayFmt)
				if spikes[k] {
					hit = true
				}
				sum += float64(s.Daily[k])
				n++
			}
			if hit {
				cur.Hits++
			}
			if b := s.BaselineBefore(o.Start); b.Days >= stats.MinBaselineDays && b.Mean >= 0.5 && n > 0 {
				cur.MultSum += (sum / float64(n)) / b.Mean
				cur.MultN++
			}
			ss[o.SignalID] = cur
		}

		// Learn organization-specific recurring overlays.
		overlays := learnOverlays(id, name, s, spikes, occs, valid, today, ss)
		res.Overlays = append(res.Overlays, overlays...)

		// Apply analyst feedback counts.
		for sig, cur := range ss {
			if f, ok := fb[fbKey(id, sig)]; ok {
				cur.Confirms, cur.Overrides = f.Confirms, f.Overrides
				ss[sig] = cur
			}
		}
		res.Stats[id] = ss

		// Label recent spike days.
		for _, d := range spikeList {
			if d.Before(windowStart) {
				continue
			}
			c := e.label(id, name, s, d, occs, res.Overlays, ss, fedNotes)
			prev, hadPrev := old[ctxID(id, c.Date)]
			c.AutoLabel = c.Label
			if hadPrev && prev.Feedback != "" {
				applyRetained(&c, prev)
			}
			c.UpdatedAt = now
			if strings.HasPrefix(c.Label, "expected") {
				if res.explained[id] == nil {
					res.explained[id] = map[string]bool{}
				}
				res.explained[id][c.Date] = true
			}
			ctxOut = append(ctxOut, c)
		}
	}
	res.Contexts = ctxOut

	if err := e.persist(res, now); err != nil {
		return res, err
	}
	return res, nil
}

func applyRetained(c *Context, prev Context) {
	c.Feedback, c.FeedbackNote, c.FeedbackSignal, c.FeedbackAt = prev.Feedback, prev.FeedbackNote, prev.FeedbackSignal, prev.FeedbackAt
	switch prev.Feedback {
	case "confirmed":
		c.Reasoning = append(c.Reasoning, fmt.Sprintf("Analyst confirmed this label on %s.", prev.FeedbackAt))
	case "overridden":
		if prev.FeedbackSignal != "" {
			c.Label = LabelExpectedLocal
			c.MatchedSignals = []string{prev.FeedbackSignal}
			c.Confidence = 1
			c.Reasoning = append(c.Reasoning, fmt.Sprintf("Analyst override on %s: attributed to signal %q. %s", prev.FeedbackAt, prev.FeedbackSignal, prev.FeedbackNote))
		} else {
			c.Label = LabelUnexplained
			c.Reasoning = append(c.Reasoning, fmt.Sprintf("Analyst override on %s: label rejected, treat as unexplained. %s", prev.FeedbackAt, prev.FeedbackNote))
		}
	}
}

func (e *Engine) label(id, name string, s *stats.DetectorStats, day time.Time, occs, overlays []ethcal.Occurrence,
	ss map[string]SigStat, fedNotes map[string]string) Context {

	b := s.BaselineBefore(day)
	count := s.Daily[day.Format(stats.DayFmt)]
	c := Context{
		DetectorID: id, DetectorName: name, Date: day.Format(stats.DayFmt), EthiopianDate: ethcal.FormatEthiopian(day),
		Count: count, BaselineMean: round2(b.Mean), BaselineStd: round2(b.Std), Threshold: round2(b.Threshold()),
		BaselineDays: b.Days, MatchedSignals: []string{}, Label: LabelUnexplained,
	}
	if b.Mean > 0 {
		c.Ratio = round2(float64(count) / b.Mean)
	}
	if b.Mean < 0.05 {
		c.Reasoning = append(c.Reasoning, fmt.Sprintf(
			"%s had %d findings on %s (%s). It is normally almost silent (%.2f/day over %d days; the spike threshold is %.1f), so this is an extreme burst rather than a mild rise.",
			name, count, c.Date, c.EthiopianDate, b.Mean, b.Days, b.Threshold()))
	} else {
		c.Reasoning = append(c.Reasoning, fmt.Sprintf(
			"%s had %d findings on %s (%s). Its normal is %.1f/day (std %.1f over %d days); the spike threshold is %.1f, so this day is %.1fx normal.",
			name, count, c.Date, c.EthiopianDate, b.Mean, b.Std, b.Days, b.Threshold(), c.Ratio))
	}

	type cand struct {
		o    ethcal.Occurrence
		conf float64
		st   SigStat
	}
	var cands []cand
	consider := func(o ethcal.Occurrence) {
		if !o.Contains(day) {
			return
		}
		st := ss[o.SignalID]
		cands = append(cands, cand{o: o, st: st, conf: confidence(o.Prior, st)})
	}
	for _, o := range occs {
		consider(o)
	}
	for _, o := range overlays {
		if o.DetectorID == id {
			consider(o)
		}
	}
	if len(cands) == 0 {
		c.Reasoning = append(c.Reasoning, "No Ethiopian calendar signal, custom signal or learned organization pattern covers this date, so nothing explains the spike. Escalate.")
		return c
	}
	sort.Slice(cands, func(i, j int) bool { return cands[i].conf > cands[j].conf })

	var best *cand
	var rejected []string
	for i := range cands {
		cd := &cands[i]
		switch {
		case cd.o.Effect == ethcal.EffectDrop:
			rejected = append(rejected, fmt.Sprintf("%q expects a volume DROP but volume spiked; a spike on a quiet day is itself suspicious", cd.o.Name))
		case cd.conf < e.Cfg.MinConfidence:
			rejected = append(rejected, fmt.Sprintf("%q matched the date but confidence %.2f is below the minimum %.2f", cd.o.Name, cd.conf, e.Cfg.MinConfidence))
		default:
			if best == nil {
				best = cd
			}
		}
	}
	if best == nil {
		c.Reasoning = append(c.Reasoning, "Signals covering this date were considered but rejected: "+strings.Join(rejected, "; ")+". Escalate.")
		return c
	}
	o := best.o
	c.Label = LabelExpectedLocal
	src := "calendar"
	if o.Source == "learned-overlay" {
		c.Label = LabelExpectedOrg
		src = "learned organization pattern"
	}
	c.MatchedSignals = []string{o.SignalID}
	c.Confidence = round2(best.conf)
	c.Reasoning = append(c.Reasoning, fmt.Sprintf("Matched %s signal %q (%s to %s; source: %s; expected effect: %s).",
		src, o.Name, o.Start.Format(stats.DayFmt), o.End.Format(stats.DayFmt), o.Source, o.Effect))
	if best.st.Trials > 0 {
		c.Reasoning = append(c.Reasoning, fmt.Sprintf("History: in %d of %d earlier occurrences of this signal this detector also spiked (%.0f%%).",
			best.st.Hits, best.st.Trials, 100*float64(best.st.Hits)/float64(best.st.Trials)))
	} else {
		c.Reasoning = append(c.Reasoning, fmt.Sprintf("History: no earlier occurrence of this signal had enough data for this detector, so the prior %.2f is used.", o.Prior))
	}
	if n := fedNotes[o.SignalID]; n != "" {
		c.Reasoning = append(c.Reasoning, "Prior "+n+".")
	}
	if o.Approximate {
		c.Reasoning = append(c.Reasoning, "Note: this signal's dates are approximate (+-1-2 days).")
	}
	if o.Source == "builtin-default-assumption" {
		c.Reasoning = append(c.Reasoning, "Note: this signal is a default assumption; confirm real dates in calendar_custom.json.")
	}
	if best.st.Confirms+best.st.Overrides > 0 {
		c.Reasoning = append(c.Reasoning, fmt.Sprintf("Analyst feedback so far: %d confirmations, %d overrides.", best.st.Confirms, best.st.Overrides))
	}
	c.Reasoning = append(c.Reasoning, fmt.Sprintf("Confidence %.2f = (hits %d + 2 x prior %.2f + confirms %d) / (trials %d + 2 + feedback %d). Label: %s.",
		best.conf, best.st.Hits, o.Prior, best.st.Confirms, best.st.Trials, best.st.Confirms+best.st.Overrides, c.Label))
	if len(rejected) > 0 {
		c.Reasoning = append(c.Reasoning, "Also considered and rejected: "+strings.Join(rejected, "; ")+".")
	}
	return c
}

func round2(v float64) float64 {
	if v < 0 {
		return -float64(int(-v*100+0.5)) / 100
	}
	return float64(int(v*100+0.5)) / 100
}

// learnOverlays discovers day-of-month patterns (Gregorian and Ethiopian)
// on which this detector reliably spikes and that no built-in or custom
// signal already explains - e.g. a bank's month-end batch job.
func learnOverlays(id, name string, s *stats.DetectorStats, spikes map[string]bool, occs []ethcal.Occurrence,
	valid, today time.Time, ss map[string]SigStat) []ethcal.Occurrence {

	if !valid.Before(today) {
		return nil
	}
	type tally struct {
		trials, hits int
		hitDays      []time.Time
	}
	greg := map[int]*tally{}
	eth := map[int]*tally{}
	get := func(m map[int]*tally, k int) *tally {
		if m[k] == nil {
			m[k] = &tally{}
		}
		return m[k]
	}
	for t := valid; !t.After(today); t = t.AddDate(0, 0, 1) {
		sp := spikes[t.Format(stats.DayFmt)]
		g := get(greg, t.Day())
		g.trials++
		_, _, ed := ethcal.CivilToEthiopian(t)
		e := get(eth, ed)
		e.trials++
		if sp {
			g.hits++
			g.hitDays = append(g.hitDays, t)
			e.hits++
			e.hitDays = append(e.hitDays, t)
		}
	}
	explained := func(d time.Time) bool {
		for _, o := range occs {
			if o.Contains(d) {
				return true
			}
		}
		return false
	}
	var out []ethcal.Occurrence
	emit := func(kind string, k int, tl *tally) {
		if tl.hits < 3 || tl.trials < 4 || float64(tl.hits)/float64(tl.trials) < 0.6 {
			return
		}
		cov := 0
		for _, d := range tl.hitDays {
			if explained(d) {
				cov++
			}
		}
		if float64(cov)/float64(len(tl.hitDays)) >= 0.7 {
			return // already explained by a calendar signal
		}
		sid := fmt.Sprintf("org-%s-dom-%02d", kind, k)
		label := "Gregorian"
		if kind == "eth" {
			label = "Ethiopian"
		}
		cur := ss[sid]
		cur.Hits, cur.Trials = tl.hits, tl.trials
		ss[sid] = cur
		from := today.AddDate(0, 0, -400)
		to := today.AddDate(0, 0, 120)
		for t := from; !t.After(to); t = t.AddDate(0, 0, 1) {
			match := t.Day() == k
			if kind == "eth" {
				_, _, ed := ethcal.CivilToEthiopian(t)
				match = ed == k
			}
			if match {
				out = append(out, ethcal.Occurrence{SignalID: sid, Name: fmt.Sprintf("Recurring spike on day %d of the %s month (learned for %s)", k, label, name),
					Start: t, End: t, Effect: ethcal.EffectSpike, Scope: "detector-specific", Prior: 0.5, Source: "learned-overlay", DetectorID: id,
					Notes: fmt.Sprintf("Learned: spiked in %d of %d such days.", tl.hits, tl.trials)})
			}
		}
	}
	keys := func(m map[int]*tally) []int {
		var k []int
		for i := range m {
			k = append(k, i)
		}
		sort.Ints(k)
		return k
	}
	for _, k := range keys(greg) {
		emit("greg", k, greg[k])
	}
	for _, k := range keys(eth) {
		emit("eth", k, eth[k])
	}
	return out
}

func (e *Engine) persist(res *Result, now string) error {
	var items []osclient.BulkItem
	calIdx := e.Cfg.IndexName(indices.CalendarSignal)
	lo, hi := res.Today.AddDate(0, 0, -400), res.Today.AddDate(0, 0, 400)
	toDoc := func(o ethcal.Occurrence) occDoc {
		return occDoc{SignalID: o.SignalID, Name: o.Name,
			DateRange: map[string]any{"gte": o.Start.Format(stats.DayFmt), "lte": o.End.Format(stats.DayFmt)},
			Effect:    o.Effect, Scope: o.Scope, Confidence: o.Prior, Recurring: true, Notes: o.Notes, Kind: "occurrence",
			Source: o.Source, DetectorID: o.DetectorID, Approx: o.Approximate, UpdatedAt: now}
	}
	for _, o := range res.Occurrences {
		if o.End.Before(lo) || o.Start.After(hi) {
			continue
		}
		items = append(items, osclient.BulkItem{Action: "index", Index: calIdx, ID: "occ:" + o.SignalID + ":" + o.Start.Format(stats.DayFmt), Doc: toDoc(o)})
	}
	for _, o := range res.Overlays {
		items = append(items, osclient.BulkItem{Action: "index", Index: calIdx, ID: "occ:" + o.SignalID + ":" + o.DetectorID + ":" + o.Start.Format(stats.DayFmt), Doc: toDoc(o)})
	}
	priors := map[string]float64{}
	for _, o := range res.Occurrences {
		priors[o.SignalID] = o.Prior
	}
	for det, m := range res.Stats {
		for sig, s := range m {
			if s.Trials == 0 {
				continue
			}
			p, ok := priors[sig]
			if !ok {
				p = 0.5
			}
			items = append(items, osclient.BulkItem{Action: "index", Index: calIdx, ID: "stat:" + det + ":" + sig, Doc: occDoc{
				SignalID: sig, Name: sig, Confidence: confidence(p, s), Kind: "stat", DetectorID: det,
				Hits: s.Hits, Trials: s.Trials, Confirms: s.Confirms, Overrides: s.Overrides, UpdatedAt: now}})
		}
	}
	ctxIdx := e.Cfg.IndexName(indices.FindingContext)
	for _, c := range res.Contexts {
		items = append(items, osclient.BulkItem{Action: "index", Index: ctxIdx, ID: ctxID(c.DetectorID, c.Date), Doc: c})
	}
	fails, err := e.Client.Bulk(items, true)
	if err != nil {
		return fmt.Errorf("writing temporal results: %w", err)
	}
	if len(fails) > 0 {
		return fmt.Errorf("%d temporal documents failed to write, first: %s", len(fails), fails[0])
	}
	return nil
}

// ApplyFeedback records an analyst decision on one detector-day context.
// action is "confirm" or "override". For an override of an unexplained day,
// signalID names the signal that actually explains it.
func ApplyFeedback(c *osclient.Client, cfg config.Config, detectorID, date, action, signalID, note string) (Context, error) {
	idx := cfg.IndexName(indices.FindingContext)
	var ctx Context
	src, found, err := c.GetDoc(idx, ctxID(detectorID, date))
	if err != nil {
		return ctx, err
	}
	if !found {
		return ctx, fmt.Errorf("no anomaly context for detector %s on %s (run 'zemen sync' first, and check the date is a spike day)", detectorID, date)
	}
	if err := json.Unmarshal(src, &ctx); err != nil {
		return ctx, err
	}
	now := time.Now().UTC().Format(time.RFC3339)
	bump := func(sig string, conf, ovr int) error {
		key := fbKey(detectorID, sig)
		var d fbDoc
		if s, ok, err := c.GetDoc(cfg.IndexName(indices.Feedback), key); err != nil {
			return err
		} else if ok {
			_ = json.Unmarshal(s, &d)
		}
		d.DetectorID, d.SignalID, d.UpdatedAt = detectorID, sig, now
		d.Confirms += conf
		d.Overrides += ovr
		return c.IndexDoc(cfg.IndexName(indices.Feedback), key, d)
	}
	switch action {
	case "confirm":
		ctx.Feedback = "confirmed"
		for _, s := range ctx.MatchedSignals {
			if err := bump(s, 1, 0); err != nil {
				return ctx, err
			}
		}
	case "override":
		ctx.Feedback = "overridden"
		if signalID != "" {
			ctx.FeedbackSignal = signalID
			ctx.Label = LabelExpectedLocal
			ctx.MatchedSignals = []string{signalID}
			ctx.Confidence = 1
			if err := bump(signalID, 1, 0); err != nil {
				return ctx, err
			}
		} else {
			if !strings.HasPrefix(ctx.AutoLabel, "expected") {
				return ctx, fmt.Errorf("this day is already labeled unexplained; to override it, say what explains it with --signal <signal_id>")
			}
			ctx.Label = LabelUnexplained
			for _, s := range ctx.MatchedSignals {
				if err := bump(s, 0, 1); err != nil {
					return ctx, err
				}
			}
		}
	default:
		return ctx, fmt.Errorf("action must be confirm or override")
	}
	ctx.FeedbackNote, ctx.FeedbackAt, ctx.UpdatedAt = note, now, now
	return ctx, c.IndexDoc(idx, ctxID(detectorID, date), ctx)
}

// LoadContexts returns stored contexts, newest day first.
func LoadContexts(c *osclient.Client, cfg config.Config) ([]Context, error) {
	hits, err := osclient.AllDocs[Context](c, cfg.IndexName(indices.FindingContext))
	if err != nil {
		return nil, err
	}
	out := make([]Context, 0, len(hits))
	for _, h := range hits {
		out = append(out, h.Source)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Date != out[j].Date {
			return out[i].Date > out[j].Date
		}
		return out[i].DetectorName < out[j].DetectorName
	})
	return out, nil
}
