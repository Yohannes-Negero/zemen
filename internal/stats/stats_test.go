package stats

import (
	"testing"
	"time"

	"zemen/internal/secanalytics"
)

func TestEpisodesAndSpikes(t *testing.T) {
	loc := time.FixedZone("x", 3*3600)
	base := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	var fs []secanalytics.Finding
	for d := 0; d < 40; d++ {
		for k := 0; k < 2; k++ {
			fs = append(fs, secanalytics.Finding{ID: "a", DetectorID: "D", Timestamp: base.AddDate(0, 0, d).Add(time.Duration(k) * time.Hour).UnixMilli()})
		}
	}
	spike := base.AddDate(0, 0, 40)
	for k := 0; k < 40; k++ {
		fs = append(fs, secanalytics.Finding{ID: "b", DetectorID: "D", Timestamp: spike.Add(time.Duration(k) * time.Minute).UnixMilli()})
	}
	st := Build(fs, loc)["D"]
	days := st.SpikeDays(st.FirstDay, Civil(spike, loc))
	if len(days) != 1 || days[0].Format(DayFmt) != Civil(spike, loc).Format(DayFmt) {
		t.Fatalf("expected exactly the spike day, got %v", days)
	}
	eps := EpisodeStarts(st.Timestamps, 30*time.Minute)
	if len(eps) < 40 {
		t.Fatalf("expected >=40 episodes, got %d", len(eps))
	}
	if q := Quantile([]float64{1, 2, 3, 4, 5}, 0.5); q != 3 {
		t.Fatalf("median = %v", q)
	}
}
