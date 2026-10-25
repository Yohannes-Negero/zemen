// Package attack holds a curated MITRE ATT&CK Enterprise matrix subset,
// technique-ID normalization, tag suggestions, and a STIX importer so a
// team can load the complete official matrix.
package attack

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// Tactic is one matrix column.
type Tactic struct {
	ID         string
	Name       string
	Techniques []string // parent technique IDs
}

// Matrix is the active matrix (curated subset unless imported).
type Matrix struct {
	Tactics []Tactic
	Names   map[string]string
	Source  string
}

var idRe = regexp.MustCompile(`(?i)^T\d{4}(\.\d{3})?$`)

// Valid reports whether s looks like an ATT&CK technique ID.
func Valid(s string) bool { return idRe.MatchString(strings.TrimSpace(s)) }

// Normalize upper-cases an ID and returns (id, parent).
func Normalize(s string) (id, parent string) {
	id = strings.ToUpper(strings.TrimSpace(s))
	parent = id
	if i := strings.Index(id, "."); i > 0 {
		parent = id[:i]
	}
	return
}

type tdef struct{ id, name string }

var curated = []struct {
	id, name string
	techs    []tdef
}{
	{"TA0043", "Reconnaissance", []tdef{{"T1595", "Active Scanning"}, {"T1590", "Gather Victim Network Information"}, {"T1589", "Gather Victim Identity Information"}}},
	{"TA0001", "Initial Access", []tdef{{"T1190", "Exploit Public-Facing Application"}, {"T1133", "External Remote Services"}, {"T1566", "Phishing"}, {"T1078", "Valid Accounts"}, {"T1195", "Supply Chain Compromise"}, {"T1189", "Drive-by Compromise"}}},
	{"TA0002", "Execution", []tdef{{"T1059", "Command and Scripting Interpreter"}, {"T1204", "User Execution"}, {"T1047", "Windows Management Instrumentation"}, {"T1053", "Scheduled Task/Job"}, {"T1569", "System Services"}, {"T1203", "Exploitation for Client Execution"}}},
	{"TA0003", "Persistence", []tdef{{"T1547", "Boot or Logon Autostart Execution"}, {"T1543", "Create or Modify System Process"}, {"T1136", "Create Account"}, {"T1505", "Server Software Component"}, {"T1098", "Account Manipulation"}, {"T1546", "Event Triggered Execution"}, {"T1574", "Hijack Execution Flow"}}},
	{"TA0004", "Privilege Escalation", []tdef{{"T1548", "Abuse Elevation Control Mechanism"}, {"T1068", "Exploitation for Privilege Escalation"}, {"T1055", "Process Injection"}, {"T1134", "Access Token Manipulation"}}},
	{"TA0005", "Defense Evasion", []tdef{{"T1070", "Indicator Removal"}, {"T1027", "Obfuscated Files or Information"}, {"T1562", "Impair Defenses"}, {"T1036", "Masquerading"}, {"T1112", "Modify Registry"}, {"T1218", "System Binary Proxy Execution"}, {"T1222", "File and Directory Permissions Modification"}}},
	{"TA0006", "Credential Access", []tdef{{"T1110", "Brute Force"}, {"T1003", "OS Credential Dumping"}, {"T1555", "Credentials from Password Stores"}, {"T1558", "Steal or Forge Kerberos Tickets"}, {"T1552", "Unsecured Credentials"}, {"T1056", "Input Capture"}, {"T1539", "Steal Web Session Cookie"}}},
	{"TA0007", "Discovery", []tdef{{"T1087", "Account Discovery"}, {"T1083", "File and Directory Discovery"}, {"T1046", "Network Service Discovery"}, {"T1018", "Remote System Discovery"}, {"T1057", "Process Discovery"}, {"T1082", "System Information Discovery"}, {"T1069", "Permission Groups Discovery"}, {"T1049", "System Network Connections Discovery"}}},
	{"TA0008", "Lateral Movement", []tdef{{"T1021", "Remote Services"}, {"T1550", "Use Alternate Authentication Material"}, {"T1570", "Lateral Tool Transfer"}, {"T1210", "Exploitation of Remote Services"}}},
	{"TA0009", "Collection", []tdef{{"T1005", "Data from Local System"}, {"T1039", "Data from Network Shared Drive"}, {"T1560", "Archive Collected Data"}, {"T1119", "Automated Collection"}, {"T1213", "Data from Information Repositories"}}},
	{"TA0011", "Command and Control", []tdef{{"T1071", "Application Layer Protocol"}, {"T1105", "Ingress Tool Transfer"}, {"T1572", "Protocol Tunneling"}, {"T1090", "Proxy"}, {"T1573", "Encrypted Channel"}, {"T1095", "Non-Application Layer Protocol"}}},
	{"TA0010", "Exfiltration", []tdef{{"T1041", "Exfiltration Over C2 Channel"}, {"T1048", "Exfiltration Over Alternative Protocol"}, {"T1567", "Exfiltration Over Web Service"}, {"T1030", "Data Transfer Size Limits"}}},
	{"TA0040", "Impact", []tdef{{"T1486", "Data Encrypted for Impact"}, {"T1490", "Inhibit System Recovery"}, {"T1485", "Data Destruction"}, {"T1565", "Data Manipulation"}, {"T1489", "Service Stop"}, {"T1499", "Endpoint Denial of Service"}}},
}

// Default returns the curated matrix subset.
func Default() *Matrix {
	m := &Matrix{Names: map[string]string{}, Source: "curated subset (run 'zemen attack-import <enterprise-attack.json>' for the full matrix)"}
	for _, t := range curated {
		tt := Tactic{ID: t.id, Name: t.name}
		for _, te := range t.techs {
			tt.Techniques = append(tt.Techniques, te.id)
			m.Names[te.id] = te.name
		}
		m.Tactics = append(m.Tactics, tt)
	}
	return m
}

// Contains reports whether a (parent) technique is in the matrix.
func (m *Matrix) Contains(parent string) bool { _, ok := m.Names[parent]; return ok }

// Load returns the imported matrix from dir if present, else the default.
func Load(dir string) *Matrix {
	b, err := os.ReadFile(filepath.Join(dir, "attack_matrix.json"))
	if err != nil {
		return Default()
	}
	var saved struct {
		Source  string `json:"source"`
		Tactics []struct {
			ID, Name   string
			Techniques []string
		} `json:"tactics"`
		Names map[string]string `json:"names"`
	}
	if json.Unmarshal(b, &saved) != nil || len(saved.Tactics) == 0 {
		return Default()
	}
	m := &Matrix{Names: saved.Names, Source: saved.Source}
	for _, t := range saved.Tactics {
		m.Tactics = append(m.Tactics, Tactic{ID: t.ID, Name: t.Name, Techniques: t.Techniques})
	}
	return m
}

// ImportSTIX reads MITRE's enterprise-attack STIX bundle and saves the
// full matrix (parent techniques) to dir/attack_matrix.json. Tactics and
// their order come from the bundle itself (the matrix object's tactic_refs),
// not from a hard-coded list, because MITRE restructures tactics between
// versions (e.g. "Defense Evasion" was split into "Stealth" and "Defense
// Impairment").
func ImportSTIX(path, dir string) (*Matrix, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var bundle struct {
		Objects []struct {
			Type       string   `json:"type"`
			ID         string   `json:"id"`
			Name       string   `json:"name"`
			Revoked    bool     `json:"revoked"`
			Deprecated bool     `json:"x_mitre_deprecated"`
			Sub        bool     `json:"x_mitre_is_subtechnique"`
			ShortName  string   `json:"x_mitre_shortname"`
			TacticRefs []string `json:"tactic_refs"`
			ExtRefs    []struct {
				Source string `json:"source_name"`
				ID     string `json:"external_id"`
			} `json:"external_references"`
			Phases []struct {
				Phase string `json:"phase_name"`
			} `json:"kill_chain_phases"`
		} `json:"objects"`
	}
	if err := json.Unmarshal(b, &bundle); err != nil {
		return nil, fmt.Errorf("not a STIX bundle: %w", err)
	}
	type tinfo struct{ id, name, short string }
	tacticByRef := map[string]tinfo{}
	tacticByShort := map[string]tinfo{}
	byTactic := map[string][]string{}
	var order []string // tactic short names in matrix order
	m := &Matrix{Names: map[string]string{}, Source: "imported from " + path}
	for _, o := range bundle.Objects {
		if o.Revoked || o.Deprecated {
			continue
		}
		var ext string
		for _, r := range o.ExtRefs {
			if r.Source == "mitre-attack" {
				ext = r.ID
			}
		}
		switch o.Type {
		case "x-mitre-tactic":
			ti := tinfo{id: ext, name: o.Name, short: o.ShortName}
			tacticByRef[o.ID] = ti
			tacticByShort[o.ShortName] = ti
		case "x-mitre-matrix":
			if len(order) == 0 {
				for _, ref := range o.TacticRefs {
					order = append(order, ref)
				}
			}
		case "attack-pattern":
			if o.Sub || ext == "" {
				continue
			}
			m.Names[ext] = o.Name
			for _, p := range o.Phases {
				byTactic[p.Phase] = append(byTactic[p.Phase], ext)
			}
		}
	}
	emitted := map[string]bool{}
	emit := func(ti tinfo) {
		ids := byTactic[ti.short]
		if len(ids) == 0 || emitted[ti.short] {
			return
		}
		emitted[ti.short] = true
		seen := map[string]bool{}
		var uniq []string
		for _, id := range ids {
			if !seen[id] {
				seen[id] = true
				uniq = append(uniq, id)
			}
		}
		sort.Strings(uniq)
		m.Tactics = append(m.Tactics, Tactic{ID: ti.id, Name: ti.name, Techniques: uniq})
	}
	for _, ref := range order {
		if ti, ok := tacticByRef[ref]; ok {
			emit(ti)
		}
	}
	// Any tactic with techniques that the matrix object did not list.
	var rest []string
	for short := range byTactic {
		rest = append(rest, short)
	}
	sort.Strings(rest)
	for _, short := range rest {
		if ti, ok := tacticByShort[short]; ok {
			emit(ti)
		} else {
			emit(tinfo{name: short, short: short})
		}
	}
	if len(m.Tactics) == 0 {
		return nil, fmt.Errorf("no techniques found - is this the enterprise-attack bundle?")
	}
	var tactOut []map[string]any
	for _, t := range m.Tactics {
		tactOut = append(tactOut, map[string]any{"ID": t.ID, "Name": t.Name, "Techniques": t.Techniques})
	}
	out, _ := json.MarshalIndent(map[string]any{"source": m.Source, "tactics": tactOut, "names": m.Names}, "", " ")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	return m, os.WriteFile(filepath.Join(dir, "attack_matrix.json"), out, 0o644)
}

// Suggestion is an unconfirmed technique suggestion with its evidence.
type Suggestion struct {
	Technique string
	Reason    string
}

var sigmaTag = regexp.MustCompile(`(?i)attack\.(t\d{4}(?:\.\d{3})?)`)

type kw struct {
	words []string
	tech  string
}

var keywords = []kw{
	{[]string{"brute force", "bruteforce", "password authentication failed", "failed login", "failed password", "authentication failure"}, "T1110"},
	{[]string{"sql injection", "sqli", "or 1=1", "union select", "sql_injection"}, "T1190"},
	{[]string{"powershell", "pwsh"}, "T1059.001"},
	{[]string{"cmd.exe", "bash -c", "command interpreter", "scripting"}, "T1059"},
	{[]string{"sudo", "setuid", "elevation"}, "T1548"},
	{[]string{"mimikatz", "lsass", "credential dump", "sam dump", "ntds"}, "T1003"},
	{[]string{"kerberoast", "golden ticket", "kerberos"}, "T1558"},
	{[]string{"scheduled task", "schtasks", "crontab"}, "T1053"},
	{[]string{"new user", "useradd", "net user", "create account", "role created", "create role"}, "T1136"},
	{[]string{"registry run", "autorun", "startup folder"}, "T1547"},
	{[]string{"log cleared", "clear log", "wevtutil", "history -c", "indicator removal"}, "T1070"},
	{[]string{"port scan", "nmap", "network scan", "service discovery"}, "T1046"},
	{[]string{"rdp", "ssh login", "psexec", "winrm", "remote service"}, "T1021"},
	{[]string{"ransom", "encrypted for impact", "mass file rename"}, "T1486"},
	{[]string{"file integrity", "fim", "file modified", "file changed", "integrity"}, "T1565"},
	{[]string{"webshell", "web shell"}, "T1505"},
	{[]string{"dns tunnel", "tunnel"}, "T1572"},
	{[]string{"exfil", "large upload", "data transfer"}, "T1048"},
	{[]string{"phish"}, "T1566"},
	{[]string{"vpn", "external remote"}, "T1133"},
	{[]string{"valid account", "impossible travel", "unusual login"}, "T1078"},
	{[]string{"service stop", "stopped service"}, "T1489"},
	{[]string{"syntax error", "sql error", "error:"}, "T1190"},
}

// Suggest proposes techniques from Sigma tags, detector name/type and rule
// names. Suggestions are never applied automatically.
func Suggest(m *Matrix, texts []string, tags []string) []Suggestion {
	seen := map[string]bool{}
	var out []Suggestion
	add := func(id, why string) {
		key, parent := Normalize(id)
		if !m.Contains(parent) || seen[key] {
			return
		}
		seen[key] = true
		out = append(out, Suggestion{Technique: key, Reason: why})
	}
	for _, t := range tags {
		if g := sigmaTag.FindStringSubmatch(t); g != nil {
			add(g[1], "rule carries Sigma tag "+t)
		}
	}
	for _, txt := range texts {
		l := strings.ToLower(txt)
		for _, k := range keywords {
			for _, w := range k.words {
				if strings.Contains(l, w) {
					add(k.tech, fmt.Sprintf("name/rule text mentions %q", w))
					break
				}
			}
		}
	}
	return out
}

// Cell states for the coverage heatmap.
const (
	CellUncovered = "uncovered" // no detector claims it
	CellVerified  = "verified"  // healthy detector AND a passing Replay Court case
	CellHealthy   = "healthy"   // healthy detector, not replay-verified
	CellDegraded  = "degraded"  // claimed, but every claiming detector is silent/noisy/disabled/no-data
)

// CoverageDetector is the minimal detector view needed for the heatmap.
type CoverageDetector struct {
	ID, Name, Status string
	Techniques       []string
}

// Cell is one technique in the heatmap.
type Cell struct {
	Technique string   `json:"technique"`
	Name      string   `json:"name"`
	State     string   `json:"state"`
	Detectors []string `json:"detectors"`
}

// ColumnOut is one tactic column of cells.
type ColumnOut struct {
	Tactic string `json:"tactic"`
	Cells  []Cell `json:"cells"`
}

// Coverage builds the heatmap. verified is the set of parent technique IDs
// with a recent passing replay case.
func (m *Matrix) Coverage(dets []CoverageDetector, verified map[string]bool) ([]ColumnOut, map[string]int) {
	claims := map[string][]CoverageDetector{}
	for _, d := range dets {
		seen := map[string]bool{}
		for _, t := range d.Techniques {
			_, p := Normalize(t)
			if !seen[p] {
				seen[p] = true
				claims[p] = append(claims[p], d)
			}
		}
	}
	counts := map[string]int{}
	var cols []ColumnOut
	for _, t := range m.Tactics {
		col := ColumnOut{Tactic: t.Name}
		for _, id := range t.Techniques {
			c := Cell{Technique: id, Name: m.Names[id], State: CellUncovered, Detectors: []string{}}
			ds := claims[id]
			healthy := false
			for _, d := range ds {
				c.Detectors = append(c.Detectors, d.Name)
				if d.Status == "healthy" || d.Status == "never_fired" {
					healthy = true
				}
			}
			switch {
			case len(ds) == 0:
			case healthy && verified[id]:
				c.State = CellVerified
			case healthy:
				c.State = CellHealthy
			default:
				c.State = CellDegraded
			}
			counts[c.State]++
			col.Cells = append(col.Cells, c)
		}
		cols = append(cols, col)
	}
	return cols, counts
}
