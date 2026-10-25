package attack

import (
	"os"
	"path/filepath"
	"testing"
)

// A miniature bundle using MITRE's current tactic names (Stealth and
// Defense Impairment instead of Defense Evasion) to guard against the
// importer depending on a hard-coded tactic list.
const miniSTIX = `{"type":"bundle","objects":[
 {"type":"x-mitre-tactic","id":"x-mitre-tactic--1","name":"Initial Access","x_mitre_shortname":"initial-access","external_references":[{"source_name":"mitre-attack","external_id":"TA0001"}]},
 {"type":"x-mitre-tactic","id":"x-mitre-tactic--2","name":"Stealth","x_mitre_shortname":"stealth","external_references":[{"source_name":"mitre-attack","external_id":"TA0005"}]},
 {"type":"x-mitre-tactic","id":"x-mitre-tactic--3","name":"Defense Impairment","x_mitre_shortname":"defense-impairment","external_references":[{"source_name":"mitre-attack","external_id":"TA0112"}]},
 {"type":"x-mitre-matrix","id":"x-mitre-matrix--1","name":"Enterprise ATT&CK","tactic_refs":["x-mitre-tactic--1","x-mitre-tactic--2","x-mitre-tactic--3"]},
 {"type":"attack-pattern","name":"Exploit Public-Facing Application","kill_chain_phases":[{"phase_name":"initial-access"}],"external_references":[{"source_name":"mitre-attack","external_id":"T1190"}]},
 {"type":"attack-pattern","name":"Indicator Removal","kill_chain_phases":[{"phase_name":"stealth"},{"phase_name":"defense-impairment"}],"external_references":[{"source_name":"mitre-attack","external_id":"T1070"}]},
 {"type":"attack-pattern","name":"Clear Logs","x_mitre_is_subtechnique":true,"kill_chain_phases":[{"phase_name":"stealth"}],"external_references":[{"source_name":"mitre-attack","external_id":"T1070.001"}]},
 {"type":"attack-pattern","name":"Old thing","revoked":true,"kill_chain_phases":[{"phase_name":"stealth"}],"external_references":[{"source_name":"mitre-attack","external_id":"T9999"}]}
]}`

func TestImportSTIXFollowsBundleTactics(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "b.json")
	if err := os.WriteFile(f, []byte(miniSTIX), 0o644); err != nil {
		t.Fatal(err)
	}
	m, err := ImportSTIX(f, dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Tactics) != 3 || m.Tactics[0].Name != "Initial Access" || m.Tactics[1].Name != "Stealth" || m.Tactics[2].Name != "Defense Impairment" {
		t.Fatalf("tactics = %+v", m.Tactics)
	}
	if !m.Contains("T1070") || !m.Contains("T1190") {
		t.Error("expected T1070 and T1190 in the matrix")
	}
	if m.Contains("T1070.001") || m.Contains("T9999") {
		t.Error("sub-techniques and revoked techniques must not be parent entries")
	}
	if got := Load(dir); !got.Contains("T1070") {
		t.Error("saved matrix must reload")
	}
}

func TestNormalizeAndSuggest(t *testing.T) {
	if id, p := Normalize(" t1059.001 "); id != "T1059.001" || p != "T1059" {
		t.Errorf("Normalize = %s %s", id, p)
	}
	if Valid("T12") || !Valid("T1110") || !Valid("t1059.001") {
		t.Error("Valid misjudged")
	}
	sg := Suggest(Default(), []string{"Brute force attack rule"}, []string{"attack.t1003"})
	got := map[string]bool{}
	for _, s := range sg {
		got[s.Technique] = true
	}
	if !got["T1110"] || !got["T1003"] {
		t.Errorf("suggestions = %+v", sg)
	}
}
