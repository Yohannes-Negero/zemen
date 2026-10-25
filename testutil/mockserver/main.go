// Command mockserver is a test double for an OpenSearch cluster with the
// Security Analytics plugin, used to exercise Zemen end to end without a
// real deployment. It generates ~17k findings over 460 days with planted
// patterns (calendar spikes, a learnable day-15 batch job, a silent
// detector, a noisy detector...) and its detectors react to replayed
// events. It is NOT part of the shipped tool.
//
// Env: MOCK_ADDR (default 127.0.0.1:9201), MOCK_IGNORE_STARTINDEX=1,
// MOCK_IGNORE_DETECTOR_FILTER=1 to simulate clusters lacking those params.
// Like real OpenSearch it refuses any listing where startIndex+size > 10000.
package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"zemen/internal/ethcal"
	"zemen/internal/osclient"
)

type detector struct {
	ID, Name, Type string
	Enabled        bool
	Indices        []string
	Keywords       []string // a replayed doc whose message contains one makes it fire
	Broken         bool     // never fires on replay
	QueryName      string
	Tags           []string
}

type finding struct {
	ID, DetectorID, Index string
	TS                    int64
	Related               []string
	Query                 string
	Tags                  []string
}

type server struct {
	mu       sync.Mutex
	indices  map[string]bool
	docs     map[string]map[string]json.RawMessage
	dets     []detector
	findings []finding
	hooks    []string
	nextID   int
	edited   bool // set by POST /_mock/edit_detector: simulates someone editing a detector
}

func main() {
	s := &server{indices: map[string]bool{}, docs: map[string]map[string]json.RawMessage{}}
	s.seed()
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.root)
	addr := os.Getenv("MOCK_ADDR")
	if addr == "" {
		addr = "127.0.0.1:9201"
	}
	log.Printf("mock opensearch on http://%s (%d findings, %d detectors)", addr, len(s.findings), len(s.dets))
	log.Fatal(http.ListenAndServe(addr, mux))
}

func (s *server) seed() {
	s.dets = []detector{
		{ID: "det-pg-sqli", Name: "POSTGRES-SQLI", Type: "postgresql", Enabled: true, Indices: []string{"postgres-logs*"}, Keywords: []string{"OR 1=1"}, QueryName: "sql_injection_rule", Tags: []string{"critical", "postgresql"}},
		{ID: "det-pg-brute", Name: "POSTGRES-BRUTE", Type: "postgresql", Enabled: true, Indices: []string{"postgres-logs*"}, Keywords: []string{"password authentication failed"}, QueryName: "Brute force attack rule", Tags: []string{"medium", "postgresql"}},
		{ID: "det-fim", Name: "fim-event-detector", Type: "linux", Enabled: true, Indices: []string{"fim-events*"}, Keywords: []string{"modified"}, QueryName: "fim file modified", Tags: []string{"high"}},
		{ID: "det-net", Name: "network-event-detector", Type: "network", Enabled: true, Indices: []string{"network-events*"}, Keywords: []string{"scan"}, QueryName: "network event", Tags: []string{"low"}},
		{ID: "det-legacy", Name: "legacy-windows-detector", Type: "windows", Enabled: true, Indices: []string{"winlogbeat*"}, Keywords: []string{"mimikatz"}, Broken: true, QueryName: "credential dump", Tags: []string{"attack.t1003", "high"}},
		{ID: "det-never", Name: "never-fired-detector", Type: "linux", Enabled: true, Indices: []string{"never-logs*"}, Keywords: []string{"zzz"}, QueryName: "rare", Tags: []string{"low"}},
		{ID: "det-off", Name: "disabled-detector", Type: "linux", Enabled: false, Indices: []string{"off-logs*"}, Keywords: []string{"zzz"}, QueryName: "off", Tags: nil},
		{ID: "det-prod", Name: "exact-index-detector", Type: "linux", Enabled: true, Indices: []string{"prod-exact"}, Keywords: []string{"x"}, QueryName: "exact", Tags: nil},
	}
	rng := rand.New(rand.NewSource(42))
	now := time.Now()
	loc := time.FixedZone("EAT", 3*3600)
	today := time.Date(now.In(loc).Year(), now.In(loc).Month(), now.In(loc).Day(), 0, 0, 0, 0, time.UTC)
	occ := ethcal.Generate(today.Year()-2, today.Year()+1, ethcal.Custom{})
	in := func(id string, d time.Time) bool {
		for _, o := range occ {
			if o.SignalID == id && o.Contains(d) {
				return true
			}
		}
		return false
	}
	add := func(det detector, day time.Time, n int) {
		for i := 0; i < n; i++ {
			sec := rng.Intn(86400)
			t := time.Date(day.Year(), day.Month(), day.Day(), 0, 0, 0, 0, loc).Add(time.Duration(sec) * time.Second)
			if t.After(now) {
				continue
			}
			s.nextID++
			s.findings = append(s.findings, finding{ID: fmt.Sprintf("f-%06d", s.nextID), DetectorID: det.ID, Index: det.Indices[0],
				TS: t.UnixMilli(), Query: det.QueryName, Tags: det.Tags})
		}
	}
	poisson := func(mean float64) int {
		n := int(mean)
		if rng.Float64() < mean-float64(n) {
			n++
		}
		return n + rng.Intn(3) - 1
	}
	det := func(id string) detector {
		for _, d := range s.dets {
			if d.ID == id {
				return d
			}
		}
		return detector{}
	}
	// Plant one recent spike that nothing explains: not a calendar signal, not day 15.
	spikeAgo := 5
	for k := 2; k < 30; k++ {
		d := today.AddDate(0, 0, -k)
		covered := d.Day() == 15
		for _, o := range occ {
			if o.Contains(d) {
				covered = true
			}
		}
		if !covered {
			spikeAgo = k
			break
		}
	}
	for d := today.AddDate(0, 0, -460); !d.After(today); d = d.AddDate(0, 0, 1) {
		daysAgo := int(today.Sub(d).Hours() / 24)
		// fim: calendar-driven spikes, a learnable day-15 batch job, one recent unexplained spike.
		n := poisson(4)
		if in("meskel", d) || in("enkutatash", d) {
			n *= 8
		}
		if in("gov-salary", d) {
			n *= 3
		}
		if d.Day() == 15 {
			n *= 7
		}
		if daysAgo == spikeAgo {
			n = 60
		}
		add(det("det-fim"), d, max0(n))
		// postgres brute force: Timkat spikes.
		n = poisson(6)
		if in("timkat", d) {
			n *= 5
		}
		add(det("det-pg-brute"), d, max0(n))
		add(det("det-pg-sqli"), d, max0(poisson(1)))
		// network: steady, then a recent unexplained surge.
		netMean := 14.0
		if os.Getenv("MOCK_BIG_NET") != "" {
			netMean = 45 // pushes this one detector past the 10,000-result window
		}
		n = poisson(netMean)
		if daysAgo <= 6 {
			n = 130 + rng.Intn(20)
		}
		add(det("det-net"), d, max0(n))
		// legacy: fired every day until 40 days ago, then went silent.
		if daysAgo > 40 {
			add(det("det-legacy"), d, max0(poisson(5)))
		}
	}
	sort.Slice(s.findings, func(i, j int) bool { return s.findings[i].TS < s.findings[j].TS })
}

func max0(n int) int {
	if n < 0 {
		return 0
	}
	return n
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func (s *server) root(w http.ResponseWriter, r *http.Request) {
	p := r.URL.Path
	switch {
	case p == "/" && r.Method == http.MethodGet:
		writeJSON(w, 200, map[string]any{"version": map[string]any{"number": "2.19.0", "distribution": "opensearch"}})
	case p == "/_plugins/_security_analytics/detectors/_search":
		s.detectorsSearch(w)
	case p == "/_plugins/_security_analytics/findings/_search":
		s.findingsSearch(w, r)
	case p == "/_plugins/_security_analytics/alerts":
		writeJSON(w, 200, map[string]any{"alerts": []any{}, "total_alerts": 0})
	case strings.HasPrefix(p, "/_plugins/_alerting/"):
		writeJSON(w, 200, map[string]any{"ok": true})
	case p == "/_hook" && r.Method == http.MethodPost:
		b, _ := io.ReadAll(r.Body)
		s.mu.Lock()
		s.hooks = append(s.hooks, string(b))
		s.mu.Unlock()
		writeJSON(w, 200, map[string]any{"ok": true})
	case p == "/_mock/edit_detector" && r.Method == http.MethodPost:
		s.mu.Lock()
		s.edited = true
		s.mu.Unlock()
		writeJSON(w, 200, map[string]any{"edited": true})
	case p == "/_hook/count":
		s.mu.Lock()
		n := len(s.hooks)
		s.mu.Unlock()
		writeJSON(w, 200, map[string]any{"count": n})
	case p == "/_bulk" && r.Method == http.MethodPost:
		s.bulk(w, r)
	default:
		s.indexOps(w, r)
	}
}

func (s *server) detectorsSearch(w http.ResponseWriter) {
	var hits []map[string]any
	s.mu.Lock()
	edited := s.edited
	s.mu.Unlock()
	for _, d := range s.dets {
		if edited && d.ID == "det-pg-sqli" {
			d.Indices = append(append([]string(nil), d.Indices...), "postgres-extra*")
		}
		hits = append(hits, map[string]any{"_id": d.ID, "_source": map[string]any{"detector": map[string]any{
			"name": d.Name, "detector_type": d.Type, "enabled": d.Enabled, "last_update_time": time.Now().UnixMilli(),
			"inputs":       []any{map[string]any{"detector_input": map[string]any{"indices": d.Indices, "description": ""}}},
			"monitor_id":   []string{"mon-" + d.ID},
			"workflow_ids": []string{"wf-" + d.ID},
			"schedule":     map[string]any{"period": map[string]any{"interval": 1, "unit": "MINUTES"}},
		}}})
	}
	writeJSON(w, 200, map[string]any{"hits": map[string]any{"hits": hits}})
}

func (s *server) findingsSearch(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	s.mu.Lock()
	all := append([]finding(nil), s.findings...)
	s.mu.Unlock()
	if det := q.Get("detector_id"); det != "" && os.Getenv("MOCK_IGNORE_DETECTOR_FILTER") == "" {
		var f []finding
		for _, x := range all {
			if x.DetectorID == det {
				f = append(f, x)
			}
		}
		all = f
	}
	// Default (no sortOrder) is oldest-first, mimicking the unsorted behavior seen on a real cluster.
	if q.Get("sortOrder") == "desc" {
		for i, j := 0, len(all)-1; i < j; i, j = i+1, j-1 {
			all[i], all[j] = all[j], all[i]
		}
	}
	size := 20
	if v, err := strconv.Atoi(q.Get("size")); err == nil && v > 0 {
		size = v
	}
	start := 0
	if os.Getenv("MOCK_IGNORE_STARTINDEX") == "" {
		if v, err := strconv.Atoi(q.Get("startIndex")); err == nil && v > 0 {
			start = v
		}
	}
	if start+size > 10000 { // real OpenSearch: index.max_result_window
		writeJSON(w, 500, map[string]any{"error": map[string]any{"root_cause": []any{map[string]any{"type": "alerting_exception", "reason": "all shards failed"}}, "type": "security_analytics_exception", "reason": "all shards failed"}, "status": 500})
		return
	}
	total := len(all)
	if start > len(all) {
		start = len(all)
	}
	end := start + size
	if end > len(all) {
		end = len(all)
	}
	var out []map[string]any
	for _, f := range all[start:end] {
		out = append(out, map[string]any{"detectorId": f.DetectorID, "id": f.ID, "related_doc_ids": f.Related, "index": f.Index,
			"queries":   []any{map[string]any{"id": "q", "name": f.Query, "tags": f.Tags, "query": "message: *x*"}},
			"timestamp": f.TS, "document_list": []any{}})
	}
	writeJSON(w, 200, map[string]any{"total_findings": total, "findings": out})
}

func (s *server) indexOps(w http.ResponseWriter, r *http.Request) {
	p := strings.TrimPrefix(r.URL.Path, "/")
	parts := strings.SplitN(p, "/", 2)
	index := parts[0]
	rest := ""
	if len(parts) > 1 {
		rest = parts[1]
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	switch {
	case rest == "" && r.Method == http.MethodHead:
		if s.indices[index] {
			w.WriteHeader(200)
		} else {
			w.WriteHeader(404)
		}
	case rest == "" && r.Method == http.MethodPut:
		s.indices[index] = true
		writeJSON(w, 200, map[string]any{"acknowledged": true})
	case rest == "_mapping" && r.Method == http.MethodPut:
		writeJSON(w, 200, map[string]any{"acknowledged": true})
	case rest == "_refresh":
		writeJSON(w, 200, map[string]any{"ok": true})
	case strings.HasPrefix(rest, "_doc/"):
		id := strings.TrimPrefix(rest, "_doc/")
		switch r.Method {
		case http.MethodPut:
			b, _ := io.ReadAll(r.Body)
			s.putDoc(index, id, b)
			writeJSON(w, 201, map[string]any{"_id": id, "result": "created"})
		case http.MethodGet:
			d, ok := s.docs[index][id]
			if !ok {
				writeJSON(w, 404, map[string]any{"found": false})
				return
			}
			writeJSON(w, 200, map[string]any{"_id": id, "found": true, "_source": d})
		case http.MethodDelete:
			delete(s.docs[index], id)
			writeJSON(w, 200, map[string]any{"result": "deleted"})
		}
	case rest == "_search" && r.Method == http.MethodPost:
		if !s.indices[index] && len(s.docs[index]) == 0 {
			writeJSON(w, 404, map[string]any{"error": map[string]any{"type": "index_not_found_exception"}})
			return
		}
		b, _ := io.ReadAll(r.Body)
		var q struct {
			Size  int            `json:"size"`
			Query map[string]any `json:"query"`
		}
		_ = json.Unmarshal(b, &q)
		var hits []map[string]any
		ids := make([]string, 0, len(s.docs[index]))
		for id := range s.docs[index] {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		for _, id := range ids {
			doc := s.docs[index][id]
			if term, ok := q.Query["term"].(map[string]any); ok {
				var m map[string]any
				_ = json.Unmarshal(doc, &m)
				match := true
				for k, v := range term {
					if fmt.Sprint(m[k]) != fmt.Sprint(v) {
						match = false
					}
				}
				if !match {
					continue
				}
			}
			hits = append(hits, map[string]any{"_id": id, "_source": doc})
			if q.Size > 0 && len(hits) >= q.Size {
				break
			}
		}
		writeJSON(w, 200, map[string]any{"hits": map[string]any{"hits": hits}})
	default:
		http.NotFound(w, r)
	}
}

func (s *server) putDoc(index, id string, b []byte) {
	if s.docs[index] == nil {
		s.docs[index] = map[string]json.RawMessage{}
	}
	s.indices[index] = true
	s.docs[index][id] = append(json.RawMessage(nil), b...)
}

func (s *server) bulk(w http.ResponseWriter, r *http.Request) {
	sc := bufio.NewScanner(r.Body)
	sc.Buffer(make([]byte, 1<<20), 64<<20)
	var items []map[string]any
	s.mu.Lock()
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var meta map[string]map[string]any
		if json.Unmarshal(line, &meta) != nil {
			continue
		}
		for act, m := range meta {
			index, _ := m["_index"].(string)
			id, _ := m["_id"].(string)
			switch act {
			case "index":
				if !sc.Scan() {
					break
				}
				doc := append([]byte(nil), sc.Bytes()...)
				s.putDoc(index, id, doc)
				s.maybeFire(index, id, doc)
				items = append(items, map[string]any{"index": map[string]any{"_id": id, "status": 201}})
			case "delete":
				delete(s.docs[index], id)
				items = append(items, map[string]any{"delete": map[string]any{"_id": id, "status": 200}})
			}
		}
	}
	s.mu.Unlock()
	writeJSON(w, 200, map[string]any{"errors": false, "items": items})
}

// maybeFire makes detectors react to replayed events: a doc indexed into an
// index a detector watches, containing one of its keywords, produces a
// finding 1.5s later (unless the detector is "broken").
func (s *server) maybeFire(index, docID string, doc []byte) {
	var m map[string]any
	if json.Unmarshal(doc, &m) != nil || m["zemen_replay"] == nil {
		return
	}
	msg, _ := m["message"].(string)
	for _, d := range s.dets {
		if !d.Enabled || d.Broken {
			continue
		}
		watches := false
		for _, p := range d.Indices {
			if osclient.Wildcard(p, index) {
				watches = true
			}
		}
		hit := false
		for _, k := range d.Keywords {
			if strings.Contains(msg, k) {
				hit = true
			}
		}
		if watches && hit {
			d := d
			time.AfterFunc(1500*time.Millisecond, func() {
				s.mu.Lock()
				defer s.mu.Unlock()
				s.nextID++
				s.findings = append(s.findings, finding{ID: fmt.Sprintf("f-%06d", s.nextID), DetectorID: d.ID, Index: index,
					TS: time.Now().UnixMilli(), Related: []string{docID}, Query: d.QueryName, Tags: d.Tags})
			})
		}
	}
}
