// Package web serves Zemen's built-in dashboard and JSON API. It is the
// self-service layer: guided ATT&CK tagging, replay-case management,
// anomaly feedback/override screens, lineage notes, coverage heatmap,
// debt, and forecast, all without touching code or raw indices.
package web

import (
	"crypto/subtle"
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"sort"
	"strconv"
	"time"

	"zemen/internal/attack"
	"zemen/internal/config"
	"zemen/internal/debt"
	"zemen/internal/ethcal"
	"zemen/internal/federated"
	"zemen/internal/forecast"
	"zemen/internal/health"
	"zemen/internal/lineage"
	"zemen/internal/osclient"
	"zemen/internal/pipeline"
	"zemen/internal/replay"
	"zemen/internal/secanalytics"
	"zemen/internal/stats"
	"zemen/internal/temporal"
)

//go:embed ui/index.html
var uiFS embed.FS

// Server holds dependencies for the HTTP handlers.
type Server struct {
	Client *osclient.Client
	Cfg    config.Config
}

// Handler builds the routed, authenticated handler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	sub, _ := fs.Sub(uiFS, "ui")
	mux.Handle("/", http.FileServer(http.FS(sub)))

	type method2fn struct {
		get, post func(*http.Request) (any, error)
	}
	routes := map[string]*method2fn{}
	reg := func(path string) *method2fn {
		if routes[path] == nil {
			routes[path] = &method2fn{}
		}
		return routes[path]
	}
	get := func(path string, f func(*http.Request) (any, error)) { reg(path).get = f }
	post := func(path string, f func(*http.Request) (any, error)) { reg(path).post = f }
	defer func() {
		for path, m := range routes {
			var g, p http.HandlerFunc
			if m.get != nil {
				g = s.wrap(http.MethodGet, m.get)
			}
			if m.post != nil {
				p = s.wrap(http.MethodPost, m.post)
			}
			mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
				switch {
				case r.Method == http.MethodGet && g != nil:
					g(w, r)
				case r.Method == http.MethodPost && p != nil:
					p(w, r)
				default:
					http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				}
			})
		}
	}()

	get("/api/overview", s.overview)
	get("/api/health", func(*http.Request) (any, error) { return health.LoadRecords(s.Client, s.Cfg) })
	get("/api/coverage", s.coverage)
	get("/api/tags", s.tags)
	post("/api/tags", s.setTags)
	get("/api/contexts", s.contexts)
	post("/api/feedback", s.feedback)
	get("/api/calendar", s.calendar)
	get("/api/replay", s.replayList)
	post("/api/replay/case", s.replaySave)
	post("/api/replay/load", s.replayLoad)
	post("/api/replay/run", s.replayRun)
	get("/api/lineage", s.lineageGet)
	post("/api/lineage", s.lineageAdd)
	get("/api/debt", func(*http.Request) (any, error) { return debt.Load(s.Client, s.Cfg) })
	get("/api/forecast", func(*http.Request) (any, error) { return forecast.Load(s.Client, s.Cfg) })
	post("/api/disposition", s.disposition)
	post("/api/sync", s.sync)
	get("/api/federated/export", s.fedExport)
	return mux
}

type apiErr struct {
	Code int
	Msg  string
}

func (e apiErr) Error() string { return e.Msg }

func bad(format string, a ...any) error {
	return apiErr{http.StatusBadRequest, fmt.Sprintf(format, a...)}
}

func (s *Server) wrap(method string, f func(*http.Request) (any, error)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != method {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if s.Cfg.UIToken != "" && subtle.ConstantTimeCompare([]byte(r.Header.Get("X-Zemen-Token")), []byte(s.Cfg.UIToken)) != 1 {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing or wrong token"})
			return
		}
		// Custom header blocks cross-site form posts (browsers cannot set it
		// cross-origin without a CORS preflight, which we never answer).
		if method == http.MethodPost && r.Header.Get("X-Zemen-UI") == "" {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "missing X-Zemen-UI header"})
			return
		}
		v, err := f(r)
		if err != nil {
			code := http.StatusInternalServerError
			if ae, ok := err.(apiErr); ok {
				code = ae.Code
			}
			writeJSON(w, code, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, v)
	}
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	if v == nil {
		v = []any{}
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func decode(r *http.Request, v any) error {
	r.Body = http.MaxBytesReader(nil, r.Body, 2<<20)
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		return bad("invalid JSON body: %v", err)
	}
	return nil
}

func (s *Server) overview(*http.Request) (any, error) {
	recs, err := health.LoadRecords(s.Client, s.Cfg)
	if err != nil {
		return nil, err
	}
	counts := map[string]int{}
	for _, r := range recs {
		counts[r.Status]++
	}
	rep, _ := debt.Load(s.Client, s.Cfg)
	fc, _ := forecast.Load(s.Client, s.Cfg)
	var next []forecast.Item
	for _, it := range fc {
		if it.DaysUntil >= 0 && len(next) < 6 && it.End >= time.Now().Format(stats.DayFmt) {
			next = append(next, it)
		}
	}
	ctxs, _ := temporal.LoadContexts(s.Client, s.Cfg)
	unexplained := 0
	cut := time.Now().AddDate(0, 0, -30).Format(stats.DayFmt)
	for _, c := range ctxs {
		if c.Label == temporal.LabelUnexplained && c.Date >= cut {
			unexplained++
		}
	}
	return map[string]any{
		"detectors": len(recs), "status_counts": counts,
		"debt":         map[string]any{"soc": rep.SOC, "count": rep.Count, "change30": rep.Change30, "change90": rep.Change90, "history": rep.History},
		"next_windows": next, "unexplained_30d": unexplained,
		"today_ethiopian": ethcal.FormatEthiopian(stats.Civil(time.Now(), s.Cfg.Location())),
	}, nil
}

func (s *Server) coverage(*http.Request) (any, error) {
	recs, err := health.LoadRecords(s.Client, s.Cfg)
	if err != nil {
		return nil, err
	}
	cases, _ := replay.LoadStored(s.Client, s.Cfg)
	ver, _ := replay.VerifiedTechniques(cases, s.Cfg.DebtVerifyDays, time.Now())
	var cd []attack.CoverageDetector
	for _, r := range recs {
		cd = append(cd, attack.CoverageDetector{ID: r.DetectorID, Name: r.DetectorName, Status: r.Status, Techniques: r.MitreTechniques})
	}
	m := attack.Load(s.Cfg.DataDir)
	cols, counts := m.Coverage(cd, ver)
	return map[string]any{"columns": cols, "counts": counts, "source": m.Source}, nil
}

func (s *Server) tags(*http.Request) (any, error) {
	recs, err := health.LoadRecords(s.Client, s.Cfg)
	if err != nil {
		return nil, err
	}
	m := attack.Load(s.Cfg.DataDir)
	type tech struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	var techs []tech
	for _, t := range m.Tactics {
		for _, id := range t.Techniques {
			techs = append(techs, tech{id, t.Name + " / " + m.Names[id]})
		}
	}
	return map[string]any{"detectors": recs, "techniques": techs}, nil
}

func (s *Server) setTags(r *http.Request) (any, error) {
	var in struct {
		DetectorID string   `json:"detector_id"`
		Techniques []string `json:"techniques"`
		Accept     bool     `json:"accept_suggestions"`
	}
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	m := attack.Load(s.Cfg.DataDir)
	var rec health.Record
	var err error
	if in.Accept {
		rec, err = health.AcceptSuggestions(s.Client, s.Cfg, m, in.DetectorID, in.Techniques)
	} else {
		rec, err = health.SetTags(s.Client, s.Cfg, m, in.DetectorID, in.Techniques)
	}
	if err != nil {
		return nil, bad("%v", err)
	}
	return rec, nil
}

func (s *Server) contexts(r *http.Request) (any, error) {
	all, err := temporal.LoadContexts(s.Client, s.Cfg)
	if err != nil {
		return nil, err
	}
	limit := 300
	if n, _ := strconv.Atoi(r.URL.Query().Get("limit")); n > 0 {
		limit = n
	}
	if len(all) > limit {
		all = all[:limit]
	}
	return all, nil
}

func (s *Server) feedback(r *http.Request) (any, error) {
	var in struct {
		DetectorID string `json:"detector_id"`
		Date       string `json:"date"`
		Action     string `json:"action"`
		Signal     string `json:"signal"`
		Note       string `json:"note"`
	}
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	c, err := temporal.ApplyFeedback(s.Client, s.Cfg, in.DetectorID, in.Date, in.Action, in.Signal, in.Note)
	if err != nil {
		return nil, bad("%v", err)
	}
	return c, nil
}

func (s *Server) calendar(r *http.Request) (any, error) {
	days := 120
	if n, _ := strconv.Atoi(r.URL.Query().Get("days")); n > 0 && n <= 800 {
		days = n
	}
	today := stats.Civil(time.Now(), s.Cfg.Location())
	custom, err := ethcal.LoadCustom(s.Cfg.DataDir)
	if err != nil {
		return nil, err
	}
	var out []map[string]any
	for _, o := range ethcal.Generate(today.Year()-1, today.Year()+2, custom) {
		if o.End.Before(today.AddDate(0, 0, -30)) || o.Start.After(today.AddDate(0, 0, days)) {
			continue
		}
		out = append(out, map[string]any{"signal_id": o.SignalID, "name": o.Name, "start": o.Start.Format(stats.DayFmt), "end": o.End.Format(stats.DayFmt),
			"ethiopian_start": ethcal.FormatEthiopian(o.Start), "effect": o.Effect, "source": o.Source, "approximate": o.Approximate, "notes": o.Notes, "prior": o.Prior})
	}
	sort.Slice(out, func(i, j int) bool { return out[i]["start"].(string) < out[j]["start"].(string) })
	return out, nil
}

func (s *Server) replayList(*http.Request) (any, error) {
	cases, err := replay.LoadStored(s.Client, s.Cfg)
	if err != nil {
		return nil, err
	}
	type row struct {
		CaseID          string                  `json:"case_id"`
		TechniqueID     string                  `json:"technique_id"`
		Description     string                  `json:"description"`
		TargetIndex     string                  `json:"target_index"`
		MappedDetectors []string                `json:"mapped_detectors"`
		EventCount      int                     `json:"event_count"`
		LastOverall     string                  `json:"last_overall"`
		LastRunAt       string                  `json:"last_run_at"`
		LastPassAt      string                  `json:"last_pass_at"`
		Results         []replay.DetectorResult `json:"results"`
	}
	out := []row{}
	for _, c := range cases {
		out = append(out, row{c.CaseID, c.TechniqueID, c.Description, c.TargetIndex, c.MappedDetectors, len(c.Events), c.LastOverall, c.LastRunAt, c.LastPassAt, c.Results})
	}
	return out, nil
}

func (s *Server) replaySave(r *http.Request) (any, error) {
	var cs replay.Case
	if err := decode(r, &cs); err != nil {
		return nil, err
	}
	dets, err := secanalytics.ListDetectors(s.Client)
	if err != nil {
		return nil, err
	}
	resolved, err := replay.Validate(cs, dets, attack.Load(s.Cfg.DataDir))
	if err != nil {
		return nil, bad("%v", err)
	}
	var ids []string
	for _, d := range resolved {
		ids = append(ids, d.ID)
	}
	if err := replay.Save(s.Client, s.Cfg, cs, ids, "ui"); err != nil {
		return nil, err
	}
	return map[string]any{"saved": cs.CaseID, "detectors": ids}, nil
}

func (s *Server) replayLoad(*http.Request) (any, error) {
	n, problems, err := pipeline.LoadCases(s.Client, s.Cfg)
	if err != nil {
		return nil, err
	}
	if problems == nil {
		problems = []string{}
	}
	return map[string]any{"loaded": n, "problems": problems}, nil
}

func (s *Server) replayRun(r *http.Request) (any, error) {
	var in struct {
		CaseID string `json:"case_id"`
	}
	_ = decode(r, &in)
	outs, err := pipeline.RunReplay(s.Client, s.Cfg, in.CaseID)
	if err != nil {
		return nil, bad("%v", err)
	}
	return outs, nil
}

func (s *Server) lineageGet(r *http.Request) (any, error) {
	ref := r.URL.Query().Get("detector")
	recs, err := health.LoadRecords(s.Client, s.Cfg)
	if err != nil {
		return nil, err
	}
	rec, err := health.ResolveDetector(recs, ref)
	if err != nil {
		return nil, bad("%v", err)
	}
	es, err := lineage.ForDetector(s.Client, s.Cfg, rec.DetectorID)
	if err != nil {
		return nil, err
	}
	return map[string]any{"entries": es, "biography": lineage.Biography(rec, es), "pending_reasons": lineage.PendingReasons(es)}, nil
}

func (s *Server) lineageAdd(r *http.Request) (any, error) {
	var in struct {
		DetectorID string `json:"detector_id"`
		Reason     string `json:"reason"`
		Trigger    string `json:"trigger"`
		Author     string `json:"author"`
	}
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	e, err := lineage.Add(s.Client, s.Cfg, in.DetectorID, in.Reason, in.Trigger, in.Author)
	if err != nil {
		return nil, bad("%v", err)
	}
	return e, nil
}

func (s *Server) disposition(r *http.Request) (any, error) {
	var in struct {
		FindingID  string `json:"finding_id"`
		DetectorID string `json:"detector_id"`
		Verdict    string `json:"verdict"`
		Note       string `json:"note"`
	}
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	if err := pipeline.Dispose(s.Client, s.Cfg, in.FindingID, in.DetectorID, in.Verdict, in.Note); err != nil {
		return nil, bad("%v", err)
	}
	return map[string]string{"ok": "recorded"}, nil
}

func (s *Server) sync(*http.Request) (any, error) {
	out, err := pipeline.Sync(s.Client, s.Cfg, time.Now())
	if err != nil {
		return nil, err
	}
	w := out.Warnings
	if w == nil {
		w = []string{}
	}
	return map[string]any{"detectors": len(out.Detectors), "status_counts": out.Health.Counts, "warnings": w,
		"findings_fetched": len(out.Findings.Findings), "findings_total": out.Findings.Total}, nil
}

func (s *Server) fedExport(*http.Request) (any, error) {
	dets, err := secanalytics.ListDetectors(s.Client)
	if err != nil {
		return nil, err
	}
	fr, err := secanalytics.FetchAll(s.Client, s.Cfg.FindingsMax, dets)
	if err != nil {
		return nil, err
	}
	st := stats.Build(fr.Findings, s.Cfg.Location())
	custom, err := ethcal.LoadCustom(s.Cfg.DataDir)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	return federated.Export(st, ethcal.Generate(now.Year()-4, now.Year()+1, custom), s.Cfg.DataDir, now)
}
