package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"html/template"
	"os"
	"os/signal"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"zemen/internal/attack"
	"zemen/internal/debt"
	"zemen/internal/ethcal"
	"zemen/internal/federated"
	"zemen/internal/forecast"
	"zemen/internal/health"
	"zemen/internal/indices"
	"zemen/internal/lineage"
	"zemen/internal/pipeline"
	"zemen/internal/replay"
	"zemen/internal/runner"
	"zemen/internal/secanalytics"
	"zemen/internal/stats"
	"zemen/internal/temporal"
)

func newTW() *tabwriter.Writer { return tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0) }

func resolve(e *env, ref string) (health.Record, error) {
	recs, err := health.LoadRecords(e.client, e.cfg)
	if err != nil {
		return health.Record{}, err
	}
	return health.ResolveDetector(recs, ref)
}

// splitArgs separates positional arguments from flags so flags may appear
// anywhere on the command line.
func splitArgs(fs *flag.FlagSet, args []string) ([]string, error) {
	var pos []string
	rest := args
	for len(rest) > 0 {
		if strings.HasPrefix(rest[0], "-") {
			if err := fs.Parse(rest); err != nil {
				return nil, err
			}
			rest = fs.Args()
			continue
		}
		pos = append(pos, rest[0])
		rest = rest[1:]
	}
	return pos, nil
}

func cmdInit(e *env, args []string) error {
	made, err := pipeline.Init(e.cfg)
	if err != nil {
		return err
	}
	if len(made) == 0 {
		fmt.Printf("%s already set up; nothing overwritten.\n", e.cfg.DataDir)
		return nil
	}
	fmt.Println("Created:")
	for _, m := range made {
		fmt.Println("  ", m)
	}
	fmt.Println("\nNext: set ZEMEN_OPENSEARCH_URL, then run 'zemen doctor', 'zemen init-indices', 'zemen sync'.")
	return nil
}

func cmdDoctor(e *env, args []string) error {
	ok := true
	check := func(name string, err error, detail string) {
		if err != nil {
			ok = false
			fmt.Printf("[FAIL] %s: %v\n", name, err)
		} else {
			fmt.Printf("[ ok ] %s %s\n", name, detail)
		}
	}
	b, err := e.client.Ping()
	ver := ""
	if err == nil {
		var p struct {
			Version struct{ Number, Distribution string }
		}
		if json.Unmarshal(b, &p) == nil {
			ver = fmt.Sprintf("(%s %s)", p.Version.Distribution, p.Version.Number)
		}
	}
	check("connect to "+e.cfg.BaseURL, err, ver)
	if err != nil {
		fmt.Println("       hint: 'server gave HTTP response to HTTPS client' means use http:// ; certificate errors mean set ZEMEN_OPENSEARCH_INSECURE_SKIP_VERIFY=true")
		return fmt.Errorf("cannot continue without a connection")
	}
	dets, err := secanalytics.ListDetectors(e.client)
	check("Security Analytics detectors API", err, fmt.Sprintf("(%d detector(s))", len(dets)))
	for _, d := range dets {
		fmt.Printf("         - %s  enabled=%v  watches=%v\n", d.Name, d.Enabled, d.InputIndices)
	}
	if err == nil {
		fr, ferr := secanalytics.FetchFindings(e.client, 3000)
		check("findings API (sorted, paged)", ferr, fmt.Sprintf("(total %d, fetched %d, paging stalled=%v)", fr.Total, len(fr.Findings), fr.PagingStalled))
		if ferr == nil && fr.Total > 10000 {
			fmt.Println("[ info ] more than 10,000 findings: OpenSearch cannot page past 10,000 in one listing, so Zemen fetches each detector separately")
			all, aerr := secanalytics.FetchAll(e.client, e.cfg.FindingsMax, dets)
			check("per-detector history", aerr, fmt.Sprintf("(filter verified=%v, history complete=%v)", all.FilterHonored, all.Complete))
			for _, d := range dets {
				if w, ok := all.PerDetector[d.ID]; ok {
					fmt.Printf("         - %s: %d of %d findings\n", d.Name, w.Fetched, w.Total)
				}
			}
		}
		if ferr == nil && fr.PagingStalled {
			fmt.Println("       note: paging stalled; Zemen will fall back to the per-detector filter where it can and report no_data_in_window otherwise.")
		}
		if ferr == nil && len(fr.Findings) > 0 {
			fs, ok2 := secanalytics.FetchDetectorFindings(e.client, fr.Findings[0].DetectorID, 5)
			fmt.Printf("[ info ] per-detector findings filter honored by this cluster: %v\n", ok2 && len(fs) > 0)
		}
	}
	for _, l := range indices.All {
		ex, err := e.client.IndexExists(e.cfg.IndexName(l))
		if err == nil && !ex {
			fmt.Printf("[ todo ] index %s does not exist yet: run 'zemen init-indices'\n", e.cfg.IndexName(l))
		}
	}
	custom, err := ethcal.LoadCustom(e.cfg.DataDir)
	if err == nil {
		if errs := custom.Validate(); len(errs) > 0 {
			err = fmt.Errorf("%s", strings.Join(errs, "; "))
		}
	}
	check("calendar_custom.json", err, fmt.Sprintf("(%d custom signal(s))", len(custom.Signals)))
	cases, cerrs := replay.LoadDir(pipeline.CaseDir(e.cfg))
	if len(cerrs) > 0 {
		check("replay case files", cerrs[0], "")
	} else {
		check("replay case files", nil, fmt.Sprintf("(%d case(s) found)", len(cases)))
	}
	fmt.Printf("[ info ] time zone offset: UTC%+d, today is %s\n", e.cfg.TZOffsetHours, ethcal.FormatEthiopian(stats.Civil(time.Now(), e.cfg.Location())))
	if !ok {
		return fmt.Errorf("some checks failed")
	}
	fmt.Println("\nAll checks passed.")
	return nil
}

func cmdInitIndices(e *env, args []string) error {
	tw := newTW()
	fmt.Fprintln(tw, "INDEX\tSTATUS")
	bad := false
	for _, r := range indices.EnsureAll(e.client, e.cfg) {
		switch {
		case r.Err != nil:
			fmt.Fprintf(tw, "%s\tERROR: %v\n", r.Physical, r.Err)
			bad = true
		case r.Created:
			fmt.Fprintf(tw, "%s\tcreated\n", r.Physical)
		default:
			s := "exists, fields up to date"
			if r.Warning != "" {
				s = "exists; " + r.Warning
			}
			fmt.Fprintf(tw, "%s\t%s\n", r.Physical, s)
		}
	}
	tw.Flush()
	if bad {
		return fmt.Errorf("some indices could not be created")
	}
	return nil
}

func cmdSync(e *env, args []string) error {
	out, err := pipeline.Sync(e.client, e.cfg, time.Now())
	if err != nil {
		return err
	}
	order := []string{"healthy", "silent", "noise_drowned", "noise_suspected", "never_fired", "no_data_in_window", "disabled"}
	var parts []string
	for _, k := range order {
		if n := out.Health.Counts[k]; n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, strings.ReplaceAll(k, "_", " ")))
		}
	}
	fmt.Printf("Synced %d detector(s): %s\n", len(out.Detectors), strings.Join(parts, ", "))
	fmt.Printf("Findings: fetched %d of %d total", len(out.Findings.Findings), out.Findings.Total)
	switch {
	case out.Findings.Complete && out.Findings.FilterHonored:
		fmt.Println(" (complete history for every detector; fetched per detector because this cluster limits one listing to 10,000 results)")
	case out.Findings.Complete:
		fmt.Println(" (complete history)")
	case out.Findings.FilterHonored:
		fmt.Println(" (per-detector history; see the capped detectors below, everything else is complete)")
	default:
		fmt.Println(" (TRUNCATED: this cluster limits one listing to 10,000 results and the per-detector filter could not be verified; run 'zemen doctor')")
	}
	if len(out.Truncated) > 0 {
		fmt.Printf("History capped at the newest 10,000 findings for: %s\n  (cadence and baselines use that recent history, which is normally what you want)\n", strings.Join(out.Truncated, ", "))
	}
	exp, unexp := 0, 0
	for _, c := range out.Temporal.Contexts {
		if strings.HasPrefix(c.Label, "expected") {
			exp++
		} else {
			unexp++
		}
	}
	fmt.Printf("Spike days (last %d days): %d explained by calendar/learned patterns, %d unexplained -> 'zemen anomalies'\n", e.cfg.LabelWindowDays, exp, unexp)
	fmt.Printf("Learned organization patterns: %d occurrence(s) across detectors\n", len(out.Temporal.Overlays))
	fmt.Printf("Detection debt: SOC %.1f over %d detector(s)", out.Debt.SOC, out.Debt.Count)
	if out.Debt.Change30 != nil {
		fmt.Printf(" (%+.1f%% vs 30 days ago)", *out.Debt.Change30)
	}
	fmt.Println()
	next := 0
	for _, f := range out.Forecast {
		if f.DaysUntil <= e.cfg.ForecastLeadDays && next < 3 {
			fmt.Printf("Upcoming: %s in %d day(s) - %s\n", f.Name, f.DaysUntil, trunc(f.Summary, 110))
			next++
		}
	}
	if out.Notified > 0 {
		fmt.Printf("Sent %d forecast notification(s)\n", out.Notified)
	}
	for _, w := range out.Warnings {
		fmt.Println("WARNING:", w)
	}
	return nil
}

func cmdStatus(e *env, args []string) error {
	recs, err := health.LoadRecords(e.client, e.cfg)
	if err != nil {
		return err
	}
	if len(recs) == 0 {
		fmt.Println("No health records yet. Run 'zemen init-indices' then 'zemen sync'.")
		return nil
	}
	tw := newTW()
	fmt.Fprintln(tw, "DETECTOR\tSTATUS\tLAST FIRED\tSILENT AFTER\tNOISE\tTECHNIQUES\tWHY")
	for _, r := range recs {
		last := "never"
		if r.LastFiredAt != nil {
			last = strings.Replace(strings.TrimSuffix(*r.LastFiredAt, "Z"), "T", " ", 1)
		}
		noise := r.FPBasis
		if r.FPBasis != "none" && r.FPBasis != "" {
			noise = fmt.Sprintf("%s %.2f", r.FPBasis, r.FPTrendScore)
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%.1fd (%s)\t%s\t%s\t%s\n", r.DetectorName, r.Status, last, r.SilenceThresholdHrs/24, r.CadenceBasis, noise,
			strings.Join(r.MitreTechniques, ","), trunc(r.StatusReason, 90))
	}
	return tw.Flush()
}

var heat = template.Must(template.New("h").Parse(`<!doctype html><meta charset="utf-8"><title>Zemen ATT&CK coverage</title>
<style>body{font:13px system-ui;background:#0f1720;color:#e6edf3;margin:20px}.m{display:flex;gap:6px;overflow-x:auto}.c{min-width:150px}
h4{margin:0 0 6px;color:#8fa3b5;font-size:12px}.x{padding:6px 8px;border-radius:5px;margin-bottom:4px;font-size:12px}
.uncovered{background:#232e3b;color:#7f90a3}.healthy{background:#1f6f4d}.verified{background:#2e9e6b}.degraded{background:#a8434f}</style>
<h2>ATT&CK coverage - {{.Date}}</h2><p>{{range $k,$v := .Counts}}{{$k}}: {{$v}} &nbsp; {{end}}</p><p>Matrix: {{.Source}}</p>
<div class="m">{{range .Cols}}<div class="c"><h4>{{.Tactic}}</h4>{{range .Cells}}<div class="x {{.State}}" title="{{range .Detectors}}{{.}}; {{end}}">{{.Technique}} {{.Name}}</div>{{end}}</div>{{end}}</div>`))

func cmdCoverage(e *env, args []string) error {
	fs := flag.NewFlagSet("coverage", flag.ContinueOnError)
	htmlOut := fs.String("html", "", "write a standalone HTML heatmap to this file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	recs, err := health.LoadRecords(e.client, e.cfg)
	if err != nil {
		return err
	}
	cases, _ := replay.LoadStored(e.client, e.cfg)
	ver, _ := replay.VerifiedTechniques(cases, e.cfg.DebtVerifyDays, time.Now())
	var cd []attack.CoverageDetector
	for _, r := range recs {
		cd = append(cd, attack.CoverageDetector{ID: r.DetectorID, Name: r.DetectorName, Status: r.Status, Techniques: r.MitreTechniques})
	}
	m := attack.Load(e.cfg.DataDir)
	cols, counts := m.Coverage(cd, ver)
	if *htmlOut != "" {
		f, err := os.Create(*htmlOut)
		if err != nil {
			return err
		}
		defer f.Close()
		if err := heat.Execute(f, map[string]any{"Cols": cols, "Counts": counts, "Source": m.Source, "Date": time.Now().Format("2006-01-02")}); err != nil {
			return err
		}
		fmt.Println("wrote", *htmlOut)
	}
	fmt.Printf("verified %d, healthy %d, degraded %d, uncovered %d   (matrix: %s)\n\n", counts["verified"], counts["healthy"], counts["degraded"], counts["uncovered"], m.Source)
	sym := map[string]string{"verified": "[V]", "healthy": "[h]", "degraded": "[!]", "uncovered": "[ ]"}
	for _, col := range cols {
		fmt.Println(col.Tactic)
		for _, c := range col.Cells {
			extra := ""
			if len(c.Detectors) > 0 {
				extra = "  <- " + strings.Join(c.Detectors, ", ")
			}
			fmt.Printf("  %s %s %s%s\n", sym[c.State], c.Technique, c.Name, extra)
		}
	}
	fmt.Println("\n[V] healthy + replay-verified   [h] healthy, unproven   [!] only silent/noisy/disabled detectors   [ ] nothing claims it")
	return nil
}

func cmdTags(e *env, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: zemen tags list | set <detector> T1110,T1190 | accept <detector> [T...] | export <file> | import <file>")
	}
	m := attack.Load(e.cfg.DataDir)
	switch args[0] {
	case "list":
		recs, err := health.LoadRecords(e.client, e.cfg)
		if err != nil {
			return err
		}
		for _, r := range recs {
			fmt.Printf("%s\n  confirmed: %s\n", r.DetectorName, orNone(strings.Join(r.MitreTechniques, ", ")))
			for _, s := range r.SuggestionReasons {
				fmt.Printf("  suggested: %s\n", s)
			}
		}
		return nil
	case "set":
		if len(args) < 3 {
			return fmt.Errorf("usage: zemen tags set <detector> T1110,T1190   (use \"\" to clear)")
		}
		rec, err := resolve(e, args[1])
		if err != nil {
			return err
		}
		r, err := health.SetTags(e.client, e.cfg, m, rec.DetectorID, strings.Split(args[2], ","))
		if err != nil {
			return err
		}
		fmt.Printf("%s now claims: %s\n", r.DetectorName, orNone(strings.Join(r.MitreTechniques, ", ")))
		return nil
	case "accept":
		if len(args) < 2 {
			return fmt.Errorf("usage: zemen tags accept <detector> [T1110 ...]")
		}
		r, err := health.AcceptSuggestions(e.client, e.cfg, m, args[1], args[2:])
		if err != nil {
			return err
		}
		fmt.Printf("%s now claims: %s\n", r.DetectorName, orNone(strings.Join(r.MitreTechniques, ", ")))
		return nil
	case "export":
		if len(args) < 2 {
			return fmt.Errorf("usage: zemen tags export <file.json>")
		}
		recs, err := health.LoadRecords(e.client, e.cfg)
		if err != nil {
			return err
		}
		out := map[string][]string{}
		for _, r := range recs {
			out[r.DetectorName] = r.MitreTechniques
		}
		b, _ := json.MarshalIndent(out, "", "  ")
		return os.WriteFile(args[1], b, 0o644)
	case "import":
		if len(args) < 2 {
			return fmt.Errorf("usage: zemen tags import <file.json>   (format: {\"Detector name\": [\"T1110\"]})")
		}
		b, err := os.ReadFile(args[1])
		if err != nil {
			return err
		}
		in := map[string][]string{}
		if err := json.Unmarshal(b, &in); err != nil {
			return err
		}
		recs, err := health.LoadRecords(e.client, e.cfg)
		if err != nil {
			return err
		}
		for ref, techs := range in {
			rec, err := health.ResolveDetector(recs, ref)
			if err != nil {
				fmt.Println("skipped:", err)
				continue
			}
			if _, err := health.SetTags(e.client, e.cfg, m, rec.DetectorID, techs); err != nil {
				fmt.Printf("skipped %s: %v\n", ref, err)
				continue
			}
			fmt.Printf("%s: %s\n", rec.DetectorName, strings.Join(techs, ", "))
		}
		return nil
	}
	return fmt.Errorf("unknown tags subcommand %q", args[0])
}

func orNone(s string) string {
	if s == "" {
		return "(none)"
	}
	return s
}

func cmdAnomalies(e *env, args []string) error {
	fs := flag.NewFlagSet("anomalies", flag.ContinueOnError)
	days := fs.Int("days", 90, "how many days back")
	vb := fs.Bool("v", false, "show the full reasoning chain")
	only := fs.String("unexplained", "", "set to 'true' to show only unexplained spikes")
	if err := fs.Parse(args); err != nil {
		return err
	}
	ctxs, err := temporal.LoadContexts(e.client, e.cfg)
	if err != nil {
		return err
	}
	cut := time.Now().AddDate(0, 0, -*days).Format(stats.DayFmt)
	n := 0
	for _, c := range ctxs {
		if c.Date < cut || (*only == "true" && c.Label != temporal.LabelUnexplained) {
			continue
		}
		n++
		fb := ""
		if c.Feedback != "" {
			fb = "  [analyst: " + c.Feedback + "]"
		}
		rt := fmt.Sprintf("%.1fx", c.Ratio)
		if c.Ratio == 0 {
			rt = "burst vs ~0"
		}
		fmt.Printf("%s (%s)  %-28s %4d findings (%s)  %s  conf %.2f%s\n", c.Date, c.EthiopianDate, c.DetectorName, c.Count, rt, c.Label, c.Confidence, fb)
		if *vb {
			for i, r := range c.Reasoning {
				fmt.Printf("    %d. %s\n", i+1, r)
			}
		}
	}
	if n == 0 {
		fmt.Println("No spike days in that range (a detector needs 14+ days of history before spikes are judged).")
	}
	return nil
}

func cmdFindings(e *env, args []string) error {
	fs := flag.NewFlagSet("findings", flag.ContinueOnError)
	n := fs.Int("n", 5, "how many findings to list")
	date := fs.String("date", "", "only findings on this local day (yyyy-mm-dd)")
	pos, err := splitArgs(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return fmt.Errorf("usage: zemen findings <detector> [-n 5] [--date yyyy-mm-dd]")
	}
	rec, err := resolve(e, pos[0])
	if err != nil {
		return err
	}
	fsr, ok := secanalytics.FetchDetectorFindings(e.client, rec.DetectorID, 1000)
	if !ok {
		all, err := secanalytics.FetchFindings(e.client, e.cfg.FindingsMax)
		if err != nil {
			return err
		}
		for _, f := range all.Findings {
			if f.DetectorID == rec.DetectorID {
				fsr = append(fsr, f)
			}
		}
	}
	loc := e.cfg.Location()
	shown := 0
	tw := newTW()
	fmt.Fprintln(tw, "FINDING ID\tFIRED (UTC)\tFIRED (LOCAL)\tDAY")
	for _, f := range fsr {
		day := stats.DayKey(f.Timestamp, loc)
		if *date != "" && day != *date {
			continue
		}
		t := time.UnixMilli(f.Timestamp)
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", f.ID, t.UTC().Format("2006-01-02 15:04:05"), t.In(loc).Format("2006-01-02 15:04:05"), day)
		shown++
		if shown >= *n {
			break
		}
	}
	tw.Flush()
	if shown == 0 {
		fmt.Printf("No findings for %s%s in the newest 1000.\n", rec.DetectorName, map[bool]string{true: " on " + *date, false: ""}[*date != ""])
	}
	return nil
}

func cmdExplain(e *env, args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: zemen explain <finding-id>")
	}
	fr, err := secanalytics.FetchFindings(e.client, e.cfg.FindingsMax)
	if err != nil {
		return err
	}
	for _, f := range fr.Findings {
		if f.ID != args[0] {
			continue
		}
		day := stats.DayKey(f.Timestamp, e.cfg.Location())
		fmt.Printf("Finding %s fired on %s (%s).\n", f.ID, day, ethcal.FormatEthiopian(stats.Civil(time.UnixMilli(f.Timestamp), e.cfg.Location())))
		ctxs, err := temporal.LoadContexts(e.client, e.cfg)
		if err != nil {
			return err
		}
		for _, c := range ctxs {
			if c.DetectorID == f.DetectorID && c.Date == day {
				fmt.Printf("That day was a spike for %s: %s (confidence %.2f)\n", c.DetectorName, c.Label, c.Confidence)
				for i, r := range c.Reasoning {
					fmt.Printf("  %d. %s\n", i+1, r)
				}
				return nil
			}
		}
		fmt.Println("That day's volume for this detector was within its normal range, so there is no calendar explanation to give. Judge the finding on its own merits.")
		return nil
	}
	return fmt.Errorf("finding %s not found in the fetched history", args[0])
}

func cmdFeedback(e *env, args []string) error {
	fs := flag.NewFlagSet("feedback", flag.ContinueOnError)
	sig := fs.String("signal", "", "signal id that actually explains the day (for overriding an unexplained label)")
	note := fs.String("note", "", "optional note")
	pos, err := splitArgs(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 3 {
		return fmt.Errorf("usage: zemen feedback <detector> <yyyy-mm-dd> confirm|override [--signal id] [--note text]")
	}
	rec, err := resolve(e, pos[0])
	if err != nil {
		return err
	}
	c, err := temporal.ApplyFeedback(e.client, e.cfg, rec.DetectorID, pos[1], pos[2], *sig, *note)
	if err != nil {
		return err
	}
	fmt.Printf("Recorded. %s on %s is now: %s (analyst %s)\n", rec.DetectorName, c.Date, c.Label, c.Feedback)
	return nil
}

func cmdDisposition(e *env, args []string) error {
	fs := flag.NewFlagSet("disposition", flag.ContinueOnError)
	det := fs.String("detector", "", "detector id (looked up from the finding if omitted)")
	note := fs.String("note", "", "optional note")
	pos, err := splitArgs(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 2 {
		return fmt.Errorf("usage: zemen disposition <finding-id> tp|fp [--detector id] [--note text]")
	}
	if err := pipeline.Dispose(e.client, e.cfg, pos[0], *det, pos[1], *note); err != nil {
		return err
	}
	fmt.Println("Recorded. Dispositions drive false-positive tracking on the next sync.")
	return nil
}

func cmdReplay(e *env, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: zemen replay template | load | list | run [case_id]")
	}
	switch args[0] {
	case "template":
		b, _ := json.MarshalIndent(replay.Template(), "", "  ")
		fmt.Println(string(b))
		return nil
	case "load":
		n, problems, err := pipeline.LoadCases(e.client, e.cfg)
		if err != nil {
			return err
		}
		fmt.Printf("Loaded %d case(s) from %s\n", n, pipeline.CaseDir(e.cfg))
		for _, p := range problems {
			fmt.Println("PROBLEM:", p)
		}
		return nil
	case "list":
		cs, err := replay.LoadStored(e.client, e.cfg)
		if err != nil {
			return err
		}
		tw := newTW()
		fmt.Fprintln(tw, "CASE\tTECHNIQUE\tDETECTORS\tLAST RESULT\tLAST RUN")
		for _, c := range cs {
			last := c.LastOverall
			if last == "" {
				last = "never run"
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", c.CaseID, c.TechniqueID, strings.Join(c.MappedDetectors, ","), last, c.LastRunAt)
		}
		return tw.Flush()
	case "run":
		id := ""
		if len(args) > 1 {
			id = args[1]
		}
		fmt.Printf("Replaying (waiting up to %s per case for detectors to fire)...\n", e.cfg.ReplayWait)
		outs, err := pipeline.RunReplay(e.client, e.cfg, id)
		if err != nil {
			return err
		}
		failed := false
		for _, o := range outs {
			fmt.Printf("\n%s: %s\n", o.CaseID, strings.ToUpper(o.Overall))
			for _, r := range o.Results {
				if r.Passed {
					fmt.Printf("  PASS  %s fired after %.0fs\n", r.DetectorName, r.LatencySeconds)
				} else {
					fmt.Printf("  FAIL  %s: %s\n", r.DetectorName, r.Error)
					failed = true
				}
			}
			for _, w := range o.Warnings {
				fmt.Println("  warning:", w)
			}
			if o.Overall == "error" {
				failed = true
			}
		}
		if failed {
			return fmt.Errorf("one or more replay checks failed")
		}
		return nil
	}
	return fmt.Errorf("unknown replay subcommand %q", args[0])
}

func cmdLineage(e *env, args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("usage: zemen lineage show <detector> | add <detector> --reason \"...\" [--trigger INC-1] [--author name]")
	}
	rec, err := resolve(e, args[1])
	if err != nil {
		return err
	}
	switch args[0] {
	case "show":
		es, err := lineage.ForDetector(e.client, e.cfg, rec.DetectorID)
		if err != nil {
			return err
		}
		fmt.Print(lineage.Biography(rec, es))
		if p := lineage.PendingReasons(es); p > 0 {
			fmt.Printf("\n%d automatic definition change(s) have no recorded reason. Add one with 'zemen lineage add'.\n", p)
		}
		return nil
	case "add":
		fs := flag.NewFlagSet("lineage add", flag.ContinueOnError)
		reason := fs.String("reason", "", "why the detector was written or changed (required)")
		trig := fs.String("trigger", "", "incident or false-positive report that prompted it")
		def := os.Getenv("USERNAME")
		if def == "" {
			def = os.Getenv("USER")
		}
		author := fs.String("author", def, "who made the judgment call")
		if err := fs.Parse(args[2:]); err != nil {
			return err
		}
		en, err := lineage.Add(e.client, e.cfg, rec.DetectorID, *reason, *trig, *author)
		if err != nil {
			return err
		}
		fmt.Printf("Recorded for %s: %s\n", rec.DetectorName, en.Reason)
		return nil
	}
	return fmt.Errorf("unknown lineage subcommand %q", args[0])
}

func cmdDebt(e *env, args []string) error {
	fs := flag.NewFlagSet("debt", flag.ContinueOnError)
	all := fs.Bool("v", false, "explain every detector, not just the top three")
	if err := fs.Parse(args); err != nil {
		return err
	}
	rep, err := debt.Load(e.client, e.cfg)
	if err != nil {
		return err
	}
	if len(rep.Rows) == 0 {
		fmt.Println("No debt computed yet. Run 'zemen sync'.")
		return nil
	}
	fmt.Printf("SOC detection debt: %.1f / 100 across %d enabled detector(s)", rep.SOC, rep.Count)
	if rep.Change30 != nil {
		fmt.Printf("   (%+.1f%% vs ~30 days ago)", *rep.Change30)
	}
	if rep.Change90 != nil {
		fmt.Printf("   (%+.1f%% vs ~90 days ago)", *rep.Change90)
	}
	fmt.Print("\n\n")
	tw := newTW()
	fmt.Fprintln(tw, "DETECTOR\tDEBT\tAGE\tFP\tCOVERAGE")
	for _, r := range rep.Rows {
		fmt.Fprintf(tw, "%s\t%.1f\t%.2f\t%.2f\t%.2f\n", r.DetectorName, r.Debt, r.Age, r.FP, r.Coverage)
	}
	tw.Flush()
	fmt.Println("\nWhy (highest debt first):")
	for i, r := range rep.Rows {
		if i >= 3 && !*all {
			break
		}
		fmt.Printf("  %s\n", r.DetectorName)
		for _, x := range r.Explanation {
			fmt.Printf("    - %s\n", x)
		}
	}
	return nil
}

func cmdForecast(e *env, args []string) error {
	items, err := forecast.Load(e.client, e.cfg)
	if err != nil {
		return err
	}
	today := time.Now().Format(stats.DayFmt)
	n := 0
	for _, it := range items {
		if it.End < today {
			continue
		}
		n++
		fmt.Printf("%s to %s  %s  (in %d day(s))\n  %s\n", it.Start, it.End, it.Name, it.DaysUntil, it.Summary)
		for _, r := range it.Recommendations {
			fmt.Printf("    * %s\n", r.Text)
		}
	}
	if n == 0 {
		fmt.Println("No forecast yet. Run 'zemen sync'.")
	}
	return nil
}

func cmdFederated(e *env, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: zemen federated export <file> | import <peer1.json> [peer2.json ...] | status")
	}
	switch args[0] {
	case "export":
		if len(args) < 2 {
			return fmt.Errorf("usage: zemen federated export <file.json>")
		}
		dets, err := secanalytics.ListDetectors(e.client)
		if err != nil {
			return err
		}
		fr, err := secanalytics.FetchAll(e.client, e.cfg.FindingsMax, dets)
		if err != nil {
			return err
		}
		custom, err := ethcal.LoadCustom(e.cfg.DataDir)
		if err != nil {
			return err
		}
		now := time.Now()
		f, err := federated.Export(stats.Build(fr.Findings, e.cfg.Location()), ethcal.Generate(now.Year()-4, now.Year()+1, custom), e.cfg.DataDir, now)
		if err != nil {
			return err
		}
		b, _ := json.MarshalIndent(f, "", "  ")
		if err := os.WriteFile(args[1], b, 0o644); err != nil {
			return err
		}
		fmt.Printf("Wrote %d anonymized signal shape(s) to %s.\nIt contains ratios-to-normal for days -3..+3 around each calendar signal. No raw logs, detector names or absolute counts.\nReview it before sharing.\n", len(f.Signals), args[1])
		return nil
	case "import":
		if len(args) < 2 {
			return fmt.Errorf("usage: zemen federated import <peer1.json> ...")
		}
		m, err := federated.Import(e.cfg.DataDir, args[1:])
		if err != nil {
			return err
		}
		fmt.Printf("Merged %d peer organization(s), %d signal(s). Priors blend in once a signal has 2+ peers. Next 'zemen sync' uses them.\n", m.Peers, len(m.Strength))
		return nil
	case "status":
		m := federated.LoadModel(e.cfg.DataDir)
		id, _ := federated.OrgID(e.cfg.DataDir)
		fmt.Printf("This installation's pseudonym: %s\nPeers merged: %d\n", id, m.Peers)
		var ks []string
		for k := range m.Strength {
			ks = append(ks, k)
		}
		sort.Strings(ks)
		for _, k := range ks {
			fmt.Printf("  %-20s peers %d, consensus strength %.2f\n", k, m.SignalPeers[k], m.Strength[k])
		}
		return nil
	}
	return fmt.Errorf("unknown federated subcommand %q", args[0])
}

func cmdCalendar(e *env, args []string) error {
	fs := flag.NewFlagSet("calendar", flag.ContinueOnError)
	days := fs.Int("days", 120, "days ahead")
	if err := fs.Parse(args); err != nil {
		return err
	}
	custom, err := ethcal.LoadCustom(e.cfg.DataDir)
	if err != nil {
		return err
	}
	if errs := custom.Validate(); len(errs) > 0 {
		return fmt.Errorf("calendar_custom.json: %s", strings.Join(errs, "; "))
	}
	today := stats.Civil(time.Now(), e.cfg.Location())
	fmt.Printf("Today: %s  (%s)\n\n", today.Format(stats.DayFmt), ethcal.FormatEthiopian(today))
	for _, o := range ethcal.Generate(today.Year(), today.Year()+1, custom) {
		if o.End.Before(today) || o.Start.After(today.AddDate(0, 0, *days)) {
			continue
		}
		ap := ""
		if o.Approximate {
			ap = " (approx.)"
		}
		fmt.Printf("%s - %s  %-45s %s  [%s]%s\n", o.Start.Format(stats.DayFmt), o.End.Format(stats.DayFmt), o.Name, strings.TrimPrefix(o.Effect, "volume_"), o.Source, ap)
	}
	return nil
}

func cmdAttackImport(e *env, args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: zemen attack-import <enterprise-attack.json>   (download from github.com/mitre-attack/attack-stix-data)")
	}
	m, err := attack.ImportSTIX(args[0], e.cfg.DataDir)
	if err != nil {
		return err
	}
	n := 0
	for _, t := range m.Tactics {
		n += len(t.Techniques)
	}
	fmt.Printf("Imported %d tactics and %d techniques into %s/attack_matrix.json\n", len(m.Tactics), n, e.cfg.DataDir)
	return nil
}

func cmdRun(e *env, args []string) error {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	noUI := fs.Bool("no-ui", false, "do not start the dashboard")
	if err := fs.Parse(args); err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	return runner.Run(ctx, e.client, e.cfg, !*noUI)
}

func cmdServe(e *env, args []string) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	return runner.Serve(ctx, e.client, e.cfg)
}
