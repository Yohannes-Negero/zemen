// Package federated implements privacy-preserving, opt-in sharing of
// calendar-pattern signatures between institutions (proposal section 7.5).
//
// A signature is only the *shape* of organization-wide event volume around
// a calendar signal (ratio to normal for days -3..+3, quantized to 0.25).
// It never contains raw logs, detector names, hostnames or absolute counts.
// Exchange is by file; no central server exists in this implementation.
package federated

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"time"

	"zemen/internal/ethcal"
	"zemen/internal/stats"
)

// SchemaVersion of the exchange format.
const SchemaVersion = 1

// Signature is one signal's shape.
type Signature struct {
	SignalID    string             `json:"signal_id"`
	Occurrences int                `json:"occurrences"`
	Offsets     map[string]float64 `json:"offsets"` // "-3".."3" -> ratio to normal
}

// File is the exchange document.
type File struct {
	Schema       int         `json:"schema"`
	OrgPseudonym string      `json:"org_pseudonym"`
	GeneratedAt  string      `json:"generated_at"`
	Signals      []Signature `json:"signals"`
}

// OrgID returns this installation's random pseudonym, creating it once.
func OrgID(dir string) (string, error) {
	p := filepath.Join(dir, "org_id")
	if b, err := os.ReadFile(p); err == nil && len(b) > 0 {
		return string(b), nil
	}
	buf := make([]byte, 8)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	id := hex.EncodeToString(buf)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	return id, os.WriteFile(p, []byte(id), 0o600)
}

func quantize(v float64) float64 { return math.Round(v*4) / 4 }

// Export builds this organization's anonymized signatures. Signals with
// fewer than 2 usable occurrences are omitted.
func Export(st map[string]*stats.DetectorStats, occs []ethcal.Occurrence, dir string, now time.Time) (File, error) {
	id, err := OrgID(dir)
	if err != nil {
		return File{}, err
	}
	total := map[string]float64{}
	var first time.Time
	for _, d := range st {
		for k, v := range d.Daily {
			total[k] += float64(v)
		}
		if first.IsZero() || d.FirstDay.Before(first) {
			first = d.FirstDay
		}
	}
	const minOcc = 2
	type acc struct {
		sum map[int]float64
		n   int
	}
	accs := map[string]*acc{}
	for _, o := range occs {
		if o.Source == "learned-overlay" || o.Start.After(now.AddDate(0, 0, -4)) || o.Start.Before(first.AddDate(0, 0, 60)) {
			continue
		}
		var bs float64
		var bn int
		for t := o.Start.AddDate(0, 0, -56); t.Before(o.Start.AddDate(0, 0, -4)); t = t.AddDate(0, 0, 1) {
			bs += total[t.Format(stats.DayFmt)]
			bn++
		}
		if bn == 0 || bs/float64(bn) < 1 {
			continue
		}
		mean := bs / float64(bn)
		a := accs[o.SignalID]
		if a == nil {
			a = &acc{sum: map[int]float64{}}
			accs[o.SignalID] = a
		}
		for off := -3; off <= 3; off++ {
			a.sum[off] += total[o.Start.AddDate(0, 0, off).Format(stats.DayFmt)] / mean
		}
		a.n++
	}
	f := File{Schema: SchemaVersion, OrgPseudonym: id, GeneratedAt: now.UTC().Format(time.RFC3339)}
	for sid, a := range accs {
		if a.n < minOcc {
			continue
		}
		sig := Signature{SignalID: sid, Occurrences: a.n, Offsets: map[string]float64{}}
		for off := -3; off <= 3; off++ {
			sig.Offsets[fmt.Sprintf("%d", off)] = quantize(a.sum[off] / float64(a.n))
		}
		f.Signals = append(f.Signals, sig)
	}
	sort.Slice(f.Signals, func(i, j int) bool { return f.Signals[i].SignalID < f.Signals[j].SignalID })
	return f, nil
}

// Model is the merged view of peer signatures.
type Model struct {
	Peers       int                `json:"peers"`
	Strength    map[string]float64 `json:"strength"`     // signal -> share of peers showing a clear shift
	SignalPeers map[string]int     `json:"signal_peers"` // signal -> number of peers that reported it
}

func shows(sig Signature) bool {
	for _, k := range []string{"0", "1"} {
		if r, ok := sig.Offsets[k]; ok && (r >= 1.5 || r <= 0.6) {
			return true
		}
	}
	return false
}

// Import merges peer files into dir/federated_model.json.
func Import(dir string, paths []string) (*Model, error) {
	own, _ := OrgID(dir)
	m := &Model{Strength: map[string]float64{}, SignalPeers: map[string]int{}}
	hits := map[string]int{}
	seenPeer := map[string]bool{}
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil {
			return nil, err
		}
		var f File
		if err := json.Unmarshal(b, &f); err != nil {
			return nil, fmt.Errorf("%s: %w", p, err)
		}
		if f.Schema != SchemaVersion {
			return nil, fmt.Errorf("%s: unsupported schema %d", p, f.Schema)
		}
		if f.OrgPseudonym == own {
			return nil, fmt.Errorf("%s is this installation's own export; import peers' files only", p)
		}
		if seenPeer[f.OrgPseudonym] {
			continue
		}
		seenPeer[f.OrgPseudonym] = true
		m.Peers++
		for _, s := range f.Signals {
			m.SignalPeers[s.SignalID]++
			if shows(s) {
				hits[s.SignalID]++
			}
		}
	}
	for sid, n := range m.SignalPeers {
		m.Strength[sid] = float64(hits[sid]) / float64(n)
	}
	out, _ := json.MarshalIndent(m, "", " ")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	return m, os.WriteFile(filepath.Join(dir, "federated_model.json"), out, 0o644)
}

// LoadModel reads the merged model, or returns an empty one.
func LoadModel(dir string) *Model {
	m := &Model{Strength: map[string]float64{}, SignalPeers: map[string]int{}}
	b, err := os.ReadFile(filepath.Join(dir, "federated_model.json"))
	if err != nil {
		return m
	}
	_ = json.Unmarshal(b, m)
	if m.Strength == nil {
		m.Strength = map[string]float64{}
	}
	if m.SignalPeers == nil {
		m.SignalPeers = map[string]int{}
	}
	return m
}

// Prior blends a built-in prior with the peer consensus. It only takes
// effect when at least two peers contributed that signal, because one
// peer's behavior says little about another's.
func (m *Model) Prior(signalID string, seed float64) (float64, string) {
	if m == nil || m.SignalPeers[signalID] < 2 {
		return seed, ""
	}
	s := m.Strength[signalID]
	return 0.5*seed + 0.5*s, fmt.Sprintf("blended with federated consensus from %d peer organizations (%.0f%% show a clear shift)", m.SignalPeers[signalID], s*100)
}
