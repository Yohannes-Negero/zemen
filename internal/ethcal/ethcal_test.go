package ethcal

import (
	"testing"
	"time"
)

func TestEthiopianKnownDates(t *testing.T) {
	cases := []struct {
		g       time.Time
		y, m, d int
	}{
		{Civil(2024, 9, 11), 2017, 1, 1},  // Enkutatash 2017
		{Civil(2023, 9, 12), 2016, 1, 1},  // after Ethiopian leap year 2015
		{Civil(2024, 9, 27), 2017, 1, 17}, // Meskel 2017
		{Civil(2026, 9, 11), 2019, 1, 1},  // Enkutatash 2019
		{Civil(2026, 1, 19), 2018, 5, 11}, // Timkat 2018
		{Civil(2000, 1, 1), 1992, 4, 22},
	}
	for _, c := range cases {
		y, m, d := CivilToEthiopian(c.g)
		if y != c.y || m != c.m || d != c.d {
			t.Errorf("CivilToEthiopian(%s) = %d-%d-%d, want %d-%d-%d", c.g.Format("2006-01-02"), y, m, d, c.y, c.m, c.d)
		}
		back := EthiopianToCivil(c.y, c.m, c.d)
		if !back.Equal(c.g) {
			t.Errorf("EthiopianToCivil(%d-%d-%d) = %s, want %s", c.y, c.m, c.d, back.Format("2006-01-02"), c.g.Format("2006-01-02"))
		}
	}
}

func TestRoundTripManyDays(t *testing.T) {
	for d := Civil(1995, 1, 1); d.Before(Civil(2045, 1, 1)); d = d.AddDate(0, 0, 1) {
		y, m, dd := CivilToEthiopian(d)
		if !EthiopianToCivil(y, m, dd).Equal(d) {
			t.Fatalf("round trip failed for %s", d.Format("2006-01-02"))
		}
		if m < 1 || m > 13 || dd < 1 || dd > 30 {
			t.Fatalf("bad ethiopian date %d-%d-%d", y, m, dd)
		}
	}
}

func TestOrthodoxEaster(t *testing.T) {
	want := map[int]time.Time{
		2024: Civil(2024, 5, 5), 2025: Civil(2025, 4, 20), 2026: Civil(2026, 4, 12), 2023: Civil(2023, 4, 16),
	}
	for y, w := range want {
		if got := OrthodoxEaster(y); !got.Equal(w) {
			t.Errorf("OrthodoxEaster(%d) = %s, want %s", y, got.Format("2006-01-02"), w.Format("2006-01-02"))
		}
	}
}

func TestIslamicApproximate(t *testing.T) {
	// 1 Ramadan 1446 was ~1 March 2025; the arithmetic calendar may differ by a day or two.
	got := IslamicToCivil(1446, 9, 1)
	want := Civil(2025, 3, 1)
	diff := got.Sub(want).Hours() / 24
	if diff < -2 || diff > 2 {
		t.Errorf("1 Ramadan 1446 = %s, expected within 2 days of 2025-03-01", got.Format("2006-01-02"))
	}
}

func TestGenerateHasCoreSignals(t *testing.T) {
	occ := Generate(2024, 2026, Custom{})
	need := map[string]bool{"enkutatash": false, "meskel": false, "timkat": false, "genna": false, "fasika": false, "lent-abiy-tsome": false, "ramadan": false, "gov-salary": false}
	for _, o := range occ {
		if _, ok := need[o.SignalID]; ok {
			need[o.SignalID] = true
		}
		if o.End.Before(o.Start) {
			t.Errorf("%s has End before Start", o.SignalID)
		}
	}
	for k, v := range need {
		if !v {
			t.Errorf("missing built-in signal %s", k)
		}
	}
	found := false
	for _, o := range occ {
		if o.SignalID == "meskel" && o.Start.Year() == 2026 {
			found = true
			if o.Start.After(Civil(2026, 9, 28)) || o.End.Before(Civil(2026, 9, 27)) {
				t.Errorf("Meskel 2026 window %s..%s does not contain Sept 27", o.Start.Format("2006-01-02"), o.End.Format("2006-01-02"))
			}
		}
	}
	if !found {
		t.Error("no Meskel occurrence in 2026")
	}
}

func TestCustomValidation(t *testing.T) {
	bad := Custom{Signals: []CustomSignal{{ID: "", Kind: "nope", Effect: "x"}}}
	if len(bad.Validate()) < 3 {
		t.Errorf("expected several validation errors, got %v", bad.Validate())
	}
	if len(Template().Validate()) != 0 {
		t.Errorf("shipped template must validate: %v", Template().Validate())
	}
}
