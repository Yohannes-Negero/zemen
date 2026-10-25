// Package secanalytics talks to the OpenSearch Security Analytics plugin:
//
//	POST /_plugins/_security_analytics/detectors/_search
//	GET  /_plugins/_security_analytics/findings/_search   (sortOrder,size,startIndex,detector_id)
//	GET  /_plugins/_security_analytics/alerts             (detector_id,size)
//
// Parsing is defensive: field names have shifted between OpenSearch
// versions, so aliases are tried in order and unexpected shapes degrade
// instead of crashing.
package secanalytics

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"zemen/internal/osclient"
)

const (
	detectorsPath = "/_plugins/_security_analytics/detectors/_search"
	findingsPath  = "/_plugins/_security_analytics/findings/_search"
	alertsPath    = "/_plugins/_security_analytics/alerts"
)

// Detector is a normalized Security Analytics detector.
type Detector struct {
	ID           string
	Name         string
	DetectorType string
	Enabled      bool
	InputIndices []string
	MonitorIDs   []string
	WorkflowIDs  []string
	Raw          map[string]any // the detector body, for snapshot/diff
}

// Finding is one time a detector fired.
type Finding struct {
	ID            string
	DetectorID    string
	Index         string
	Timestamp     int64 // epoch millis
	RelatedDocIDs []string
	QueryNames    []string
	QueryTags     []string
}

// ListDetectors returns every detector on the cluster.
func ListDetectors(c *osclient.Client) ([]Detector, error) {
	body, err := c.Post(detectorsPath, map[string]any{"size": 1000, "query": map[string]any{"match_all": map[string]any{}}})
	if err != nil {
		return nil, fmt.Errorf("listing detectors: %w", err)
	}
	var env struct {
		Hits struct {
			Hits []struct {
				ID     string         `json:"_id"`
				Source map[string]any `json:"_source"`
			} `json:"hits"`
		} `json:"hits"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		return nil, fmt.Errorf("decoding detector search response: %w", err)
	}
	out := make([]Detector, 0, len(env.Hits.Hits))
	for _, h := range env.Hits.Hits {
		f := h.Source
		if nested, ok := f["detector"].(map[string]any); ok {
			f = nested
		}
		d := Detector{
			ID: h.ID, Name: str(f, "name"), DetectorType: str(f, "detector_type", "detectorType"),
			Enabled: boolean(f, "enabled"), Raw: f,
			MonitorIDs: strList(f["monitor_id"]), WorkflowIDs: strList(f["workflow_ids"]),
		}
		if ins, ok := f["inputs"].([]any); ok {
			for _, in := range ins {
				m, _ := in.(map[string]any)
				di, _ := m["detector_input"].(map[string]any)
				d.InputIndices = append(d.InputIndices, strList(di["indices"])...)
			}
		}
		out = append(out, d)
	}
	return out, nil
}

// maxWindow is OpenSearch's default index.max_result_window: startIndex+size
// may not exceed it, so a single listing can never reach past the newest
// 10,000 findings. (Seen on a real 24,216-finding cluster: HTTP 500 "all
// shards failed" at startIndex=10000.)
const maxWindow = 10000

// DetectorWindow describes how much of one detector's history was fetched.
type DetectorWindow struct {
	Total    int  // findings the cluster reports for this detector
	Fetched  int  // findings actually retrieved (newest first)
	Complete bool // Fetched covers Total
}

// FindingsResult is the outcome of a findings pull.
type FindingsResult struct {
	Findings      []Finding
	Total         int  // cluster-wide total reported by the API
	Complete      bool // history is complete for every monitored detector
	PagingStalled bool // paging stopped making progress before completion
	WindowLimited bool // the cluster's 10,000-result window stopped the global listing
	FilterHonored bool // per-detector queries were used and verified
	PerDetector   map[string]DetectorWindow
}

// DetectorComplete reports whether the history we hold for a detector is
// the complete history (so "no findings" really means "never fired").
func (r FindingsResult) DetectorComplete(id string) bool {
	if r.Complete {
		return true
	}
	w, ok := r.PerDetector[id]
	return ok && w.Complete
}

type rawFinding struct {
	ID            string   `json:"id"`
	DetectorID    string   `json:"detectorId"`
	DetectorIDAlt string   `json:"detector_id"`
	Index         string   `json:"index"`
	Timestamp     float64  `json:"timestamp"`
	RelatedDocIDs []string `json:"related_doc_ids"`
	Queries       []struct {
		Name string   `json:"name"`
		Tags []string `json:"tags"`
	} `json:"queries"`
}

type rawFindings struct {
	TotalFindings int          `json:"total_findings"`
	Findings      []rawFinding `json:"findings"`
}

func (r rawFinding) toFinding() Finding {
	f := Finding{ID: r.ID, DetectorID: r.DetectorID, Index: r.Index, Timestamp: int64(r.Timestamp), RelatedDocIDs: r.RelatedDocIDs}
	if f.DetectorID == "" {
		f.DetectorID = r.DetectorIDAlt
	}
	for _, q := range r.Queries {
		f.QueryNames = append(f.QueryNames, q.Name)
		f.QueryTags = append(f.QueryTags, q.Tags...)
	}
	return f
}

func fetchPage(c *osclient.Client, q url.Values) (rawFindings, error) {
	body, err := c.Get(findingsPath + "?" + q.Encode())
	if err != nil {
		return rawFindings{}, err
	}
	var rf rawFindings
	if err := json.Unmarshal(body, &rf); err != nil {
		return rf, fmt.Errorf("decoding findings response: %w", err)
	}
	return rf, nil
}

// FetchFindings pages through findings newest-first until everything is
// fetched, paging stops making progress, the cluster's 10,000-result window
// is reached, or max findings were collected. An unsorted call is
// unreliable (observed on a real cluster), so sortOrder=desc is always sent.
func FetchFindings(c *osclient.Client, max int) (FindingsResult, error) {
	const pageSize = 1000
	res := FindingsResult{PerDetector: map[string]DetectorWindow{}}
	seen := map[string]bool{}
	for start := 0; len(res.Findings) < max; start += pageSize {
		if start+pageSize > maxWindow {
			res.WindowLimited = true
			break
		}
		q := url.Values{"sortOrder": {"desc"}, "size": {strconv.Itoa(pageSize)}, "startIndex": {strconv.Itoa(start)}}
		rf, err := fetchPage(c, q)
		if err != nil {
			if start == 0 {
				return res, fmt.Errorf("listing findings: %w", err)
			}
			// A cluster with a smaller result window than 10,000 fails here;
			// keep what we have and let per-detector queries fill the gaps.
			res.WindowLimited = true
			break
		}
		if start == 0 {
			res.Total = rf.TotalFindings
		}
		fresh := 0
		for _, r := range rf.Findings {
			if r.ID == "" || seen[r.ID] {
				continue
			}
			seen[r.ID] = true
			res.Findings = append(res.Findings, r.toFinding())
			fresh++
		}
		if len(rf.Findings) == 0 || len(res.Findings) >= res.Total {
			break
		}
		if fresh == 0 { // server ignored startIndex or looped
			res.PagingStalled = true
			break
		}
	}
	res.Complete = len(res.Findings) >= res.Total
	return res, nil
}

// fetchDetectorPaged pages one detector's findings via the detector_id
// filter. honored is false if the server returned any finding that does not
// belong to the detector (i.e. it ignored the filter).
func fetchDetectorPaged(c *osclient.Client, id string, max int) (fs []Finding, total int, honored bool) {
	const pageSize = 1000
	seen := map[string]bool{}
	for start := 0; len(fs) < max && start+pageSize <= maxWindow; start += pageSize {
		rf, err := fetchPage(c, url.Values{"detector_id": {id}, "sortOrder": {"desc"},
			"size": {strconv.Itoa(pageSize)}, "startIndex": {strconv.Itoa(start)}})
		if err != nil {
			if start == 0 {
				return nil, 0, false
			}
			break
		}
		if start == 0 {
			total = rf.TotalFindings
		}
		fresh := 0
		for _, r := range rf.Findings {
			f := r.toFinding()
			if f.DetectorID != id {
				return nil, 0, false
			}
			if f.ID == "" || seen[f.ID] {
				continue
			}
			seen[f.ID] = true
			fs = append(fs, f)
			fresh++
		}
		if len(rf.Findings) == 0 || len(fs) >= total || fresh == 0 {
			break
		}
	}
	return fs, total, true
}

// FetchAll gets the best history the cluster allows. It lists findings
// globally first; if the history is bigger than the cluster's result
// window it verifies that the detector_id filter really works, and then
// fetches every detector's newest findings separately. Whether a detector's
// history is complete is recorded per detector, so a detector with zero
// findings is only called "never fired" when that is actually proven.
func FetchAll(c *osclient.Client, max int, dets []Detector) (FindingsResult, error) {
	res, err := FetchFindings(c, max)
	if err != nil || res.Complete {
		return res, err
	}
	// Probe: pick a detector we saw and check the filter narrows results.
	probe := ""
	for _, f := range res.Findings {
		if f.DetectorID != "" {
			probe = f.DetectorID
			break
		}
	}
	if probe == "" {
		return res, nil
	}
	_, ptotal, ok := fetchDetectorPaged(c, probe, 1)
	if !ok || ptotal >= res.Total {
		return res, nil // filter ignored or unprovable: stay honest, stay incomplete
	}
	res.FilterHonored = true
	index := map[string]bool{}
	for _, f := range res.Findings {
		index[f.ID] = true
	}
	allComplete := true
	for _, d := range dets {
		fs, total, ok := fetchDetectorPaged(c, d.ID, max)
		if !ok {
			allComplete = false
			continue
		}
		for _, f := range fs {
			if !index[f.ID] {
				index[f.ID] = true
				res.Findings = append(res.Findings, f)
			}
		}
		w := DetectorWindow{Total: total, Fetched: len(fs), Complete: len(fs) >= total}
		res.PerDetector[d.ID] = w
		if !w.Complete {
			allComplete = false
		}
	}
	res.Complete = allComplete
	return res, nil
}

// FetchDetectorFindings asks for one detector's newest findings using the
// detector_id filter. It returns ok=false unless the server demonstrably
// honored the filter (every returned finding belongs to the detector), so
// an ignored/unsupported parameter can never mislabel a detector.
func FetchDetectorFindings(c *osclient.Client, detectorID string, size int) ([]Finding, bool) {
	rf, err := fetchPage(c, url.Values{"detector_id": {detectorID}, "sortOrder": {"desc"}, "size": {strconv.Itoa(size)}})
	if err != nil || len(rf.Findings) == 0 {
		return nil, false
	}
	out := make([]Finding, 0, len(rf.Findings))
	for _, r := range rf.Findings {
		f := r.toFinding()
		if f.DetectorID != detectorID {
			return nil, false
		}
		out = append(out, f)
	}
	return out, true
}

// Alert is a Security Analytics alert (used only for a triage-time proxy).
type Alert struct {
	ID              string
	State           string
	StartMillis     int64
	AcknowledgedMil int64
}

// ListAlerts fetches alerts for a detector. Errors are returned so
// callers can simply skip the proxy when the endpoint is unavailable.
func ListAlerts(c *osclient.Client, detectorID string, size int) ([]Alert, error) {
	body, err := c.Get(alertsPath + "?" + url.Values{"detector_id": {detectorID}, "size": {strconv.Itoa(size)}}.Encode())
	if err != nil {
		return nil, err
	}
	var env struct {
		Alerts []struct {
			ID    string          `json:"id"`
			State string          `json:"state"`
			Start json.RawMessage `json:"start_time"`
			Ack   json.RawMessage `json:"acknowledged_time"`
		} `json:"alerts"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		return nil, err
	}
	out := make([]Alert, 0, len(env.Alerts))
	for _, a := range env.Alerts {
		out = append(out, Alert{ID: a.ID, State: a.State, StartMillis: rawMillis(a.Start), AcknowledgedMil: rawMillis(a.Ack)})
	}
	return out, nil
}

func rawMillis(r json.RawMessage) int64 {
	s := strings.TrimSpace(string(r))
	if s == "" || s == "null" {
		return 0
	}
	if strings.HasPrefix(s, "\"") {
		var str string
		_ = json.Unmarshal(r, &str)
		if t, err := time.Parse(time.RFC3339, str); err == nil {
			return t.UnixMilli()
		}
		return 0
	}
	var f float64
	if json.Unmarshal(r, &f) == nil {
		return int64(f)
	}
	return 0
}

func str(m map[string]any, keys ...string) string {
	for _, k := range keys {
		if s, ok := m[k].(string); ok {
			return s
		}
	}
	return ""
}

func boolean(m map[string]any, keys ...string) bool {
	for _, k := range keys {
		if b, ok := m[k].(bool); ok {
			return b
		}
	}
	return false
}

func strList(v any) []string {
	switch t := v.(type) {
	case string:
		if t != "" {
			return []string{t}
		}
	case []any:
		var out []string
		for _, e := range t {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}
