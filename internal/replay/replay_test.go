package replay

import (
	"strings"
	"testing"

	"zemen/internal/attack"
	"zemen/internal/secanalytics"
)

func dets(indices ...string) []secanalytics.Detector {
	return []secanalytics.Detector{{ID: "d1", Name: "Det One", Enabled: true, InputIndices: indices}}
}

func base() Case {
	return Case{CaseID: "c", TechniqueID: "T1110", TargetIndex: "pg-zemen-replay", MappedDetectors: []string{"Det One"},
		Events: []map[string]any{{"message": "x"}}}
}

func TestValidateSafety(t *testing.T) {
	m := attack.Default()
	cases := []struct {
		name    string
		mod     func(*Case)
		dets    []secanalytics.Detector
		wantErr string
	}{
		{"ok on wildcard watch", func(c *Case) {}, dets("pg*"), ""},
		{"exact production index refused", func(c *Case) { c.TargetIndex = "pg" }, dets("pg"), "mixed into real logs"},
		{"production name via wildcard refused", func(c *Case) { c.TargetIndex = "pg" }, dets("pg*"), "does not look like a replay index"},
		{"unwatched index refused", func(c *Case) { c.TargetIndex = "other-replay" }, dets("pg*"), "does not include target_index"},
		{"explicit override allowed", func(c *Case) { c.TargetIndex = "pg"; c.AllowProductionIndex = true }, dets("pg*"), ""},
		{"disabled detector refused", func(c *Case) {}, []secanalytics.Detector{{ID: "d1", Name: "Det One", Enabled: false, InputIndices: []string{"pg*"}}}, "disabled"},
		{"unknown detector refused", func(c *Case) { c.MappedDetectors = []string{"Nope"} }, dets("pg*"), "no detector matches"},
		{"bad technique refused", func(c *Case) { c.TechniqueID = "banana" }, dets("pg*"), "not a valid ATT&CK id"},
		{"no events refused", func(c *Case) { c.Events = nil }, dets("pg*"), "at least one event"},
	}
	for _, tc := range cases {
		c := base()
		tc.mod(&c)
		_, err := Validate(c, tc.dets, m)
		switch {
		case tc.wantErr == "" && err != nil:
			t.Errorf("%s: unexpected error %v", tc.name, err)
		case tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)):
			t.Errorf("%s: want error containing %q, got %v", tc.name, tc.wantErr, err)
		}
	}
}
