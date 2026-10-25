// Package pipeline wires every Zemen module together in dependency order.
package pipeline

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"zemen/internal/attack"
	"zemen/internal/config"
	"zemen/internal/debt"
	"zemen/internal/ethcal"
	"zemen/internal/forecast"
	"zemen/internal/health"
	"zemen/internal/indices"
	"zemen/internal/lineage"
	"zemen/internal/osclient"
	"zemen/internal/replay"
	"zemen/internal/secanalytics"
	"zemen/internal/stats"
	"zemen/internal/temporal"
)

// Output is everything one sync produced.
type Output struct {
	Detectors []secanalytics.Detector
	Findings  secanalytics.FindingsResult
	Temporal  *temporal.Result
	Health    health.Summary
	Debt      debt.Report
	Forecast  []forecast.Item
	Notified  int
	Truncated []string // detectors whose history exceeded the cluster window (newest findings used)
	Warnings  []string
}

// Sync runs: detectors+findings -> stats -> temporal -> health -> lineage
// -> debt -> forecast (+ webhook).
func Sync(c *osclient.Client, cfg config.Config, now time.Time) (*Output, error) {
	out := &Output{}
	var err error
	if out.Detectors, err = secanalytics.ListDetectors(c); err != nil {
		return out, err
	}
	if out.Findings, err = secanalytics.FetchAll(c, cfg.FindingsMax, out.Detectors); err != nil {
		return out, err
	}
	for _, d := range out.Detectors {
		if w, ok := out.Findings.PerDetector[d.ID]; ok && !w.Complete {
			out.Truncated = append(out.Truncated, fmt.Sprintf("%s (%d of %d)", d.Name, w.Fetched, w.Total))
		}
	}
	st := stats.Build(out.Findings.Findings, cfg.Location())

	eng := &temporal.Engine{Client: c, Cfg: cfg, Now: now}
	if out.Temporal, err = eng.Run(out.Detectors, st); err != nil {
		return out, fmt.Errorf("temporal engine: %w", err)
	}

	matrix := attack.Load(cfg.DataDir)
	if out.Health, err = health.Compute(health.Params{Client: c, Cfg: cfg, Now: now, Detectors: out.Detectors,
		Findings: out.Findings, Stats: st, Explain: out.Temporal, Matrix: matrix}); err != nil {
		return out, fmt.Errorf("health radar: %w", err)
	}
	for _, e := range out.Health.Errors {
		out.Warnings = append(out.Warnings, e.Error())
	}

	if err := lineage.Observe(c, cfg, out.Detectors, out.Health, now); err != nil {
		out.Warnings = append(out.Warnings, "lineage: "+err.Error())
	}
	cases, err := replay.LoadStored(c, cfg)
	if err != nil {
		out.Warnings = append(out.Warnings, "reading replay cases: "+err.Error())
	}
	if out.Debt, err = debt.Compute(c, cfg, out.Health.Records, cases, now); err != nil {
		out.Warnings = append(out.Warnings, "debt: "+err.Error())
	}
	if out.Forecast, err = forecast.Compute(c, cfg, out.Temporal, out.Health.Records, now); err != nil {
		out.Warnings = append(out.Warnings, "forecast: "+err.Error())
	} else if out.Notified, err = forecast.Notify(c, cfg, out.Forecast, now); err != nil {
		out.Warnings = append(out.Warnings, "forecast notification: "+err.Error())
	}
	return out, nil
}

// CaseDir is where replay case files live.
func CaseDir(cfg config.Config) string { return filepath.Join(cfg.DataDir, "replay_cases") }

// LoadCases reads case files from disk, validates them against the live
// detectors, and stores the valid ones. Problems are returned, not fatal.
func LoadCases(c *osclient.Client, cfg config.Config) (loaded int, problems []string, err error) {
	dets, err := secanalytics.ListDetectors(c)
	if err != nil {
		return 0, nil, err
	}
	m := attack.Load(cfg.DataDir)
	cases, errs := replay.LoadDir(CaseDir(cfg))
	for _, e := range errs {
		problems = append(problems, e.Error())
	}
	for _, cs := range cases {
		resolved, verr := replay.Validate(cs, dets, m)
		if verr != nil {
			problems = append(problems, verr.Error())
			continue
		}
		var ids []string
		for _, d := range resolved {
			ids = append(ids, d.ID)
		}
		if err := replay.Save(c, cfg, cs, ids, "replay_cases/"); err != nil {
			problems = append(problems, fmt.Sprintf("case %s: %v", cs.CaseID, err))
			continue
		}
		loaded++
	}
	return loaded, problems, nil
}

// RunReplay runs one stored case (caseID) or all of them.
func RunReplay(c *osclient.Client, cfg config.Config, caseID string) ([]replay.RunOutcome, error) {
	dets, err := secanalytics.ListDetectors(c)
	if err != nil {
		return nil, err
	}
	stored, err := replay.LoadStored(c, cfg)
	if err != nil {
		return nil, err
	}
	m := attack.Load(cfg.DataDir)
	var outs []replay.RunOutcome
	for _, s := range stored {
		if caseID != "" && s.CaseID != caseID {
			continue
		}
		resolved, verr := replay.Validate(s.Case, dets, m)
		if verr != nil {
			outs = append(outs, replay.RunOutcome{CaseID: s.CaseID, Overall: "error", Warnings: []string{verr.Error()}})
			continue
		}
		o, rerr := replay.Run(c, cfg, s.Case, resolved, s.Results)
		if rerr != nil {
			outs = append(outs, replay.RunOutcome{CaseID: s.CaseID, Overall: "error", Warnings: []string{rerr.Error()}})
			continue
		}
		if err := replay.SaveOutcome(c, cfg, o); err != nil {
			o.Warnings = append(o.Warnings, err.Error())
		}
		if err := lineage.RecordReplay(c, cfg, s.CaseID, s.Results, o.Results); err != nil {
			o.Warnings = append(o.Warnings, err.Error())
		}
		outs = append(outs, o)
	}
	if caseID != "" && len(outs) == 0 {
		return nil, fmt.Errorf("no stored replay case %q (run 'zemen replay load' first)", caseID)
	}
	return outs, nil
}

// Dispose records an analyst's true/false-positive verdict for a finding.
func Dispose(c *osclient.Client, cfg config.Config, findingID, detectorID, verdict, note string) error {
	if verdict != "tp" && verdict != "fp" {
		return fmt.Errorf("verdict must be tp (true positive) or fp (false positive)")
	}
	if detectorID == "" {
		fr, err := secanalytics.FetchFindings(c, cfg.FindingsMax)
		if err != nil {
			return err
		}
		for _, f := range fr.Findings {
			if f.ID == findingID {
				detectorID = f.DetectorID
				break
			}
		}
		if detectorID == "" {
			return fmt.Errorf("finding %s not found; pass --detector explicitly", findingID)
		}
	}
	return c.IndexDoc(cfg.IndexName(indices.Disposition), findingID, map[string]any{
		"finding_id": findingID, "detector_id": detectorID, "verdict": verdict, "note": note, "at": time.Now().UTC().Format(time.RFC3339)})
}

// Init creates the self-service data directory with documented templates.
func Init(cfg config.Config) ([]string, error) {
	var made []string
	write := func(rel string, data []byte) error {
		p := filepath.Join(cfg.DataDir, rel)
		if _, err := os.Stat(p); err == nil {
			return nil // never overwrite the user's edits
		}
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			return err
		}
		made = append(made, p)
		return os.WriteFile(p, data, 0o644)
	}
	cal, _ := json.MarshalIndent(ethcal.Template(), "", "  ")
	if err := write("calendar_custom.json", cal); err != nil {
		return made, err
	}
	tpl, _ := json.MarshalIndent(replay.Template(), "", "  ")
	if err := write("replay_cases/TEMPLATE.json.example", tpl); err != nil {
		return made, err
	}
	ex, _ := json.MarshalIndent(replay.ExampleCases(), "", "  ")
	if err := write("replay_cases/example-postgres.json.example", ex); err != nil {
		return made, err
	}
	readme := "Zemen data directory\n\n" +
		"calendar_custom.json     add your own temporal signals (pay days, batch jobs, exam seasons) - no code needed.\n" +
		"replay_cases/*.json      Replay Court cases. Copy a *.json.example file, edit it, rename to .json, run 'zemen replay load'.\n" +
		"federated_model.json     created by 'zemen federated import'.\n" +
		"attack_matrix.json       created by 'zemen attack-import' (full MITRE matrix).\n"
	if err := write("README.txt", []byte(readme)); err != nil {
		return made, err
	}
	return made, nil
}
