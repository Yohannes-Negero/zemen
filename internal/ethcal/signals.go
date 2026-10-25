package ethcal

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Effect values describe how a signal is expected to move event volume.
const (
	EffectSpike = "volume_spike"
	EffectDrop  = "volume_drop"
	EffectMixed = "mixed"
)

// Occurrence is one dated instance of a temporal signal. Start and End are
// inclusive civil dates.
type Occurrence struct {
	SignalID    string    `json:"signal_id"`
	Name        string    `json:"name"`
	Start       time.Time `json:"start"`
	End         time.Time `json:"end"`
	Effect      string    `json:"effect"`
	Scope       string    `json:"scope"`
	Prior       float64   `json:"prior"`
	Source      string    `json:"source"` // builtin | builtin-default-assumption | custom | learned-overlay
	Notes       string    `json:"notes,omitempty"`
	Approximate bool      `json:"approximate,omitempty"`
	DetectorID  string    `json:"detector_id,omitempty"` // set for learned overlays
}

// Contains reports whether the civil date falls inside the occurrence.
func (o Occurrence) Contains(day time.Time) bool { return !day.Before(o.Start) && !day.After(o.End) }

// Custom is the self-service calendar file (zemen-data/calendar_custom.json).
type Custom struct {
	DisableBuiltin []string       `json:"disable_builtin,omitempty"`
	Signals        []CustomSignal `json:"signals,omitempty"`
}

// CustomSignal lets a security team add or override signals without code.
type CustomSignal struct {
	ID         string  `json:"id"`
	Name       string  `json:"name"`
	Kind       string  `json:"kind"` // gregorian_range | ethiopian_monthly | gregorian_monthly | ethiopian_annual | gregorian_annual
	Effect     string  `json:"effect"`
	Scope      string  `json:"scope"`
	Confidence float64 `json:"confidence"`
	Enabled    *bool   `json:"enabled,omitempty"`
	Notes      string  `json:"notes,omitempty"`
	Start      string  `json:"start,omitempty"` // gregorian_range: yyyy-mm-dd
	End        string  `json:"end,omitempty"`
	Month      int     `json:"month,omitempty"` // *_annual
	DayFrom    int     `json:"day_from,omitempty"`
	DayTo      int     `json:"day_to,omitempty"`
}

// LoadCustom reads <dir>/calendar_custom.json; a missing file is fine.
func LoadCustom(dir string) (Custom, error) {
	var c Custom
	b, err := os.ReadFile(filepath.Join(dir, "calendar_custom.json"))
	if err != nil {
		if os.IsNotExist(err) {
			return c, nil
		}
		return c, err
	}
	if err := json.Unmarshal(b, &c); err != nil {
		return c, fmt.Errorf("calendar_custom.json: %w", err)
	}
	return c, nil
}

// Validate returns human-readable problems with a custom file.
func (c Custom) Validate() []string {
	var errs []string
	seen := map[string]bool{}
	for i, s := range c.Signals {
		p := fmt.Sprintf("signals[%d] (%s)", i, s.ID)
		if s.ID == "" || s.Name == "" {
			errs = append(errs, p+": id and name are required")
		}
		if seen[s.ID] {
			errs = append(errs, p+": duplicate id")
		}
		seen[s.ID] = true
		switch s.Effect {
		case EffectSpike, EffectDrop, EffectMixed:
		default:
			errs = append(errs, p+": effect must be volume_spike, volume_drop or mixed")
		}
		if s.Confidence < 0 || s.Confidence > 1 {
			errs = append(errs, p+": confidence must be between 0 and 1")
		}
		switch s.Kind {
		case "gregorian_range":
			if _, err := time.Parse("2006-01-02", s.Start); err != nil {
				errs = append(errs, p+": start must be yyyy-mm-dd")
			}
			if _, err := time.Parse("2006-01-02", s.End); err != nil {
				errs = append(errs, p+": end must be yyyy-mm-dd")
			}
		case "ethiopian_monthly", "gregorian_monthly":
			if s.DayFrom < 1 || s.DayTo < s.DayFrom || s.DayTo > 31 {
				errs = append(errs, p+": day_from/day_to invalid")
			}
		case "ethiopian_annual", "gregorian_annual":
			if s.Month < 1 || s.Month > 13 || s.DayFrom < 1 || s.DayTo < s.DayFrom || s.DayTo > 31 {
				errs = append(errs, p+": month/day_from/day_to invalid")
			}
		default:
			errs = append(errs, p+": unknown kind "+s.Kind)
		}
	}
	return errs
}

// Template is written by `zemen init`: every extra signal ships disabled
// until the organization confirms the real dates.
func Template() Custom {
	f := false
	return Custom{
		DisableBuiltin: []string{},
		Signals: []CustomSignal{
			{ID: "pension-disbursement", Name: "Pension disbursement window (EXAMPLE - set your real dates)", Kind: "ethiopian_monthly",
				Effect: EffectSpike, Scope: "org-wide", Confidence: 0.3, Enabled: &f, DayFrom: 1, DayTo: 5,
				Notes: "Replace day_from/day_to with the real disbursement days, then set enabled to true."},
			{ID: "exam-season", Name: "National exam season (EXAMPLE)", Kind: "gregorian_annual", Month: 7,
				Effect: EffectMixed, Scope: "sector-specific", Confidence: 0.3, Enabled: &f, DayFrom: 1, DayTo: 31,
				Notes: "Education-sector example. Adjust month/days to your institution."},
			{ID: "harvest-payments", Name: "Agricultural payment cycle (EXAMPLE)", Kind: "ethiopian_annual", Month: 3,
				Effect: EffectSpike, Scope: "sector-specific", Confidence: 0.3, Enabled: &f, DayFrom: 1, DayTo: 30,
				Notes: "Example of a seasonal payment window. Adjust to your sector."},
			{ID: "bank-month-end-batch", Name: "Month-end batch processing (EXAMPLE)", Kind: "gregorian_monthly",
				Effect: EffectSpike, Scope: "org-wide", Confidence: 0.4, Enabled: &f, DayFrom: 28, DayTo: 31,
				Notes: "Example of an organization-specific batch window."},
		},
	}
}

type spec struct {
	id, name, effect, scope, source, notes string
	prior                                  float64
	approx                                 bool
}

func occ(s spec, a, b time.Time) Occurrence {
	return Occurrence{SignalID: s.id, Name: s.name, Start: a, End: b, Effect: s.effect, Scope: s.scope,
		Prior: s.prior, Source: s.source, Notes: s.notes, Approximate: s.approx}
}

// Generate returns every built-in and custom occurrence whose window
// overlaps [Jan 1 fromYear, Dec 31 toYear], sorted by start date.
func Generate(fromYear, toYear int, cu Custom) []Occurrence {
	lo, hi := Civil(fromYear, 1, 1), Civil(toYear, 12, 31)
	disabled := map[string]bool{}
	for _, id := range cu.DisableBuiltin {
		disabled[id] = true
	}
	var out []Occurrence
	add := func(o Occurrence) {
		if disabled[o.SignalID] || o.End.Before(lo) || o.Start.After(hi) {
			return
		}
		out = append(out, o)
	}

	// Ethiopian-calendar anchored signals.
	ethHoliday := func(s spec, month, day int) {
		for ey := fromYear - 9; ey <= toYear-6; ey++ {
			d := EthiopianToCivil(ey, month, day)
			add(occ(s, d.AddDate(0, 0, -1), d.AddDate(0, 0, 1)))
		}
	}
	ethHoliday(spec{id: "enkutatash", name: "Enkutatash (Ethiopian New Year)", effect: EffectMixed, scope: "org-wide", source: "builtin", prior: 0.5,
		notes: "Meskerem 1. Window covers the eve and the day after."}, 1, 1)
	ethHoliday(spec{id: "meskel", name: "Meskel (Finding of the True Cross)", effect: EffectMixed, scope: "org-wide", source: "builtin", prior: 0.5,
		notes: "Meskerem 17."}, 1, 17)
	ethHoliday(spec{id: "genna", name: "Genna (Ethiopian Christmas)", effect: EffectMixed, scope: "org-wide", source: "builtin", prior: 0.5,
		notes: "Tahsas 29."}, 4, 29)
	ethHoliday(spec{id: "timkat", name: "Timkat (Epiphany)", effect: EffectMixed, scope: "org-wide", source: "builtin", prior: 0.5,
		notes: "Tir 11."}, 5, 11)
	ethHoliday(spec{id: "adwa-victory", name: "Adwa Victory Day", effect: EffectDrop, scope: "org-wide", source: "builtin", prior: 0.4,
		notes: "Yekatit 23 (public holiday)."}, 6, 23)
	ethHoliday(spec{id: "patriots-victory", name: "Patriots' Victory Day", effect: EffectDrop, scope: "org-wide", source: "builtin", prior: 0.4,
		notes: "Miazia 27 (public holiday)."}, 8, 27)
	ethHoliday(spec{id: "derg-downfall", name: "Downfall of the Derg", effect: EffectDrop, scope: "org-wide", source: "builtin", prior: 0.4,
		notes: "Ginbot 20 (public holiday)."}, 9, 20)

	// Fasting seasons fixed by the Ethiopian calendar.
	for ey := fromYear - 9; ey <= toYear-6; ey++ {
		add(occ(spec{id: "filseta", name: "Filseta (Dormition fast)", effect: EffectMixed, scope: "org-wide", source: "builtin", prior: 0.3,
			notes: "Nehase 1-16. Behavioral effect is indirect; confidence is learned locally."},
			EthiopianToCivil(ey, 12, 1), EthiopianToCivil(ey, 12, 16)))
		add(occ(spec{id: "advent-fast", name: "Advent / Nativity fast (Tsome Nebiyat)", effect: EffectMixed, scope: "org-wide", source: "builtin", prior: 0.3,
			notes: "Hidar 15 to Tahsas 28."},
			EthiopianToCivil(ey, 3, 15), EthiopianToCivil(ey, 4, 28)))
	}

	// Easter-relative signals (Orthodox computus).
	for gy := fromYear - 1; gy <= toYear+1; gy++ {
		e := OrthodoxEaster(gy)
		add(occ(spec{id: "fasika", name: "Fasika (Ethiopian Easter) incl. Good Friday", effect: EffectMixed, scope: "org-wide", source: "builtin", prior: 0.5,
			notes: "Window: day before Good Friday through Easter Monday."}, e.AddDate(0, 0, -3), e.AddDate(0, 0, 1)))
		add(occ(spec{id: "lent-abiy-tsome", name: "Abiy Tsome (Great Lent, 55 days)", effect: EffectMixed, scope: "org-wide", source: "builtin", prior: 0.3,
			notes: "Starts 55 days before Easter. Fasting changes spending/transaction behavior; confidence is learned locally."},
			e.AddDate(0, 0, -55), e.AddDate(0, 0, -1)))
		start := e.AddDate(0, 0, 51)
		end := EthiopianToCivil(func() int { y, _, _ := CivilToEthiopian(start); return y }(), 11, 5)
		if !end.Before(start) {
			add(occ(spec{id: "apostles-fast", name: "Tsome Hawaryat (Apostles' fast)", effect: EffectMixed, scope: "org-wide", source: "builtin", prior: 0.25,
				notes: "Day after Pentecost through Hamle 5."}, start, end))
		}
	}

	// Gregorian-fixed public holiday.
	for gy := fromYear; gy <= toYear; gy++ {
		d := Civil(gy, 5, 1)
		add(occ(spec{id: "labour-day", name: "International Labour Day", effect: EffectDrop, scope: "org-wide", source: "builtin", prior: 0.4,
			notes: "May 1 (public holiday)."}, d.AddDate(0, 0, -1), d.AddDate(0, 0, 1)))
	}

	// Islamic signals (arithmetic calendar, approximate).
	for gy := fromYear - 1; gy <= toYear+1; gy++ {
		for hy := (gy-622)*33/32 - 1; hy <= (gy-622)*33/32+2; hy++ {
			ap := func(id, name string, eff string, a, b time.Time, note string) {
				add(occ(spec{id: id, name: name, effect: eff, scope: "org-wide", source: "builtin", prior: 0.4, approx: true,
					notes: note + " Dates come from the arithmetic Hijri calendar and may differ by 1-2 days from moon-sighting."}, a, b))
			}
			ap("ramadan", "Ramadan", EffectMixed, IslamicToCivil(hy, 9, 1), IslamicToCivil(hy, 9, 29), "Month 9.")
			f := IslamicToCivil(hy, 10, 1)
			ap("eid-al-fitr", "Eid al-Fitr", EffectMixed, f.AddDate(0, 0, -2), f.AddDate(0, 0, 2), "1 Shawwal; window covers 2 days either side.")
			a := IslamicToCivil(hy, 12, 10)
			ap("eid-al-adha", "Eid al-Adha", EffectMixed, a.AddDate(0, 0, -2), a.AddDate(0, 0, 2), "10 Dhu al-Hijjah.")
			m := IslamicToCivil(hy, 3, 12)
			ap("mawlid", "Mawlid", EffectDrop, m.AddDate(0, 0, -1), m.AddDate(0, 0, 1), "12 Rabi' al-awwal.")
		}
	}

	// Default government salary window: an ASSUMPTION, flagged as such.
	for ey := fromYear - 9; ey <= toYear-6; ey++ {
		for m := 1; m <= 12; m++ {
			add(occ(spec{id: "gov-salary", name: "Government salary window (default assumption)", effect: EffectSpike, scope: "org-wide",
				source: "builtin-default-assumption", prior: 0.3,
				notes: "ASSUMPTION: Ethiopian day 25-30 of each month. Confirm your real pay dates in calendar_custom.json (disable_builtin + a custom signal)."},
				EthiopianToCivil(ey, m, 25), EthiopianToCivil(ey, m, 30)))
		}
	}

	// Custom signals.
	for _, s := range cu.Signals {
		if s.Enabled != nil && !*s.Enabled {
			continue
		}
		sp := spec{id: s.ID, name: s.Name, effect: s.Effect, scope: s.Scope, source: "custom", prior: s.Confidence, notes: s.Notes}
		if sp.scope == "" {
			sp.scope = "org-wide"
		}
		switch s.Kind {
		case "gregorian_range":
			a, e1 := time.Parse("2006-01-02", s.Start)
			b, e2 := time.Parse("2006-01-02", s.End)
			if e1 == nil && e2 == nil {
				add(occ(sp, a, b))
			}
		case "gregorian_annual":
			for gy := fromYear; gy <= toYear; gy++ {
				add(occ(sp, clampDay(gy, s.Month, s.DayFrom), clampDay(gy, s.Month, s.DayTo)))
			}
		case "gregorian_monthly":
			for gy := fromYear; gy <= toYear; gy++ {
				for m := 1; m <= 12; m++ {
					add(occ(sp, clampDay(gy, m, s.DayFrom), clampDay(gy, m, s.DayTo)))
				}
			}
		case "ethiopian_annual":
			for ey := fromYear - 9; ey <= toYear-6; ey++ {
				add(occ(sp, EthiopianToCivil(ey, s.Month, minInt(s.DayFrom, DaysInEthiopianMonth(ey, s.Month))),
					EthiopianToCivil(ey, s.Month, minInt(s.DayTo, DaysInEthiopianMonth(ey, s.Month)))))
			}
		case "ethiopian_monthly":
			for ey := fromYear - 9; ey <= toYear-6; ey++ {
				for m := 1; m <= 13; m++ {
					n := DaysInEthiopianMonth(ey, m)
					if s.DayFrom > n {
						continue
					}
					add(occ(sp, EthiopianToCivil(ey, m, s.DayFrom), EthiopianToCivil(ey, m, minInt(s.DayTo, n))))
				}
			}
		}
	}

	sort.Slice(out, func(i, j int) bool {
		if !out[i].Start.Equal(out[j].Start) {
			return out[i].Start.Before(out[j].Start)
		}
		return strings.Compare(out[i].SignalID, out[j].SignalID) < 0
	})
	return dedupe(out)
}

func clampDay(y, m, d int) time.Time {
	last := Civil(y, m+1, 0).Day()
	if d > last {
		d = last
	}
	return Civil(y, m, d)
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func dedupe(in []Occurrence) []Occurrence {
	seen := map[string]bool{}
	var out []Occurrence
	for _, o := range in {
		k := o.SignalID + "|" + o.Start.Format("2006-01-02")
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, o)
	}
	return out
}
