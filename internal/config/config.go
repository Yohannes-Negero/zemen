// Package config loads Zemen's runtime configuration from environment
// variables (standard library only).
package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config holds everything Zemen needs. Every field has a sensible default
// except ZEMEN_OPENSEARCH_URL.
type Config struct {
	BaseURL            string
	Username           string
	Password           string
	APIKey             string
	InsecureSkipVerify bool
	IndexPrefix        string

	// DataDir holds the self-service configuration files (custom calendar
	// signals, replay case templates, the federated model, org id).
	DataDir string

	// TZOffsetHours is the local offset from UTC used to bucket findings
	// into days and to resolve calendar dates. Ethiopia (EAT) is +3.
	TZOffsetHours int

	SyncInterval       time.Duration
	ReplayInterval     time.Duration
	ReplayPollInterval time.Duration
	ReplayWait         time.Duration
	ReplayTrigger      bool

	UIAddr     string
	UIToken    string
	WebhookURL string

	ForecastLeadDays    int
	ForecastHorizonDays int

	FindingsMax     int
	DefaultSilence  time.Duration
	LabelWindowDays int
	MinConfidence   float64

	DebtVerifyDays     int
	DebtWeightAge      float64
	DebtWeightFP       float64
	DebtWeightCoverage float64
}

// Load reads configuration from the environment and requires the
// OpenSearch URL.
func Load() (Config, error) { return load(true) }

// LoadOffline reads configuration without requiring a cluster URL, for
// commands that never talk to OpenSearch (init, calendar, attack-import).
func LoadOffline() (Config, error) { return load(false) }

func load(requireURL bool) (Config, error) {
	cfg := Config{
		BaseURL:     strings.TrimRight(os.Getenv("ZEMEN_OPENSEARCH_URL"), "/"),
		Username:    os.Getenv("ZEMEN_OPENSEARCH_USERNAME"),
		Password:    os.Getenv("ZEMEN_OPENSEARCH_PASSWORD"),
		APIKey:      os.Getenv("ZEMEN_OPENSEARCH_API_KEY"),
		IndexPrefix: envStr("ZEMEN_INDEX_PREFIX", "zemen"),
		DataDir:     envStr("ZEMEN_DATA_DIR", "zemen-data"),
		UIAddr:      envStr("ZEMEN_UI_ADDR", "127.0.0.1:8080"),
		UIToken:     os.Getenv("ZEMEN_UI_TOKEN"),
		WebhookURL:  os.Getenv("ZEMEN_WEBHOOK_URL"),
	}
	if requireURL && cfg.BaseURL == "" {
		return Config{}, fmt.Errorf("ZEMEN_OPENSEARCH_URL is required (e.g. http://localhost:9200)")
	}

	var err error
	if cfg.InsecureSkipVerify, err = envBool("ZEMEN_OPENSEARCH_INSECURE_SKIP_VERIFY", false); err != nil {
		return Config{}, err
	}
	if cfg.ReplayTrigger, err = envBool("ZEMEN_REPLAY_TRIGGER", false); err != nil {
		return Config{}, err
	}
	ints := []struct {
		name string
		def  int
		dst  *int
	}{
		{"ZEMEN_TZ_OFFSET_HOURS", 3, &cfg.TZOffsetHours},
		{"ZEMEN_FORECAST_LEAD_DAYS", 7, &cfg.ForecastLeadDays},
		{"ZEMEN_FORECAST_HORIZON_DAYS", 60, &cfg.ForecastHorizonDays},
		{"ZEMEN_FINDINGS_MAX", 200000, &cfg.FindingsMax},
		{"ZEMEN_LABEL_WINDOW_DAYS", 90, &cfg.LabelWindowDays},
		{"ZEMEN_DEBT_VERIFY_DAYS", 30, &cfg.DebtVerifyDays},
	}
	for _, i := range ints {
		if *i.dst, err = envInt(i.name, i.def); err != nil {
			return Config{}, err
		}
	}
	durs := []struct {
		name string
		def  time.Duration
		dst  *time.Duration
	}{
		{"ZEMEN_SYNC_INTERVAL", 10 * time.Minute, &cfg.SyncInterval},
		{"ZEMEN_REPLAY_INTERVAL", 24 * time.Hour, &cfg.ReplayInterval},
		{"ZEMEN_REPLAY_POLL_INTERVAL", 10 * time.Second, &cfg.ReplayPollInterval},
		{"ZEMEN_REPLAY_WAIT", 3 * time.Minute, &cfg.ReplayWait},
		{"ZEMEN_DEFAULT_SILENCE", 7 * 24 * time.Hour, &cfg.DefaultSilence},
	}
	for _, d := range durs {
		if *d.dst, err = envDur(d.name, d.def); err != nil {
			return Config{}, err
		}
	}
	floats := []struct {
		name string
		def  float64
		dst  *float64
	}{
		{"ZEMEN_MIN_CONFIDENCE", 0.30, &cfg.MinConfidence},
		{"ZEMEN_DEBT_WEIGHT_AGE", 0.40, &cfg.DebtWeightAge},
		{"ZEMEN_DEBT_WEIGHT_FP", 0.30, &cfg.DebtWeightFP},
		{"ZEMEN_DEBT_WEIGHT_COVERAGE", 0.30, &cfg.DebtWeightCoverage},
	}
	for _, f := range floats {
		if *f.dst, err = envFloat(f.name, f.def); err != nil {
			return Config{}, err
		}
	}
	return cfg, nil
}

// IndexName returns the fully-qualified index name for a logical index.
func (c Config) IndexName(logical string) string { return c.IndexPrefix + "-" + logical }

// Location returns the fixed-offset local time zone used for day bucketing.
func (c Config) Location() *time.Location {
	return time.FixedZone("local", c.TZOffsetHours*3600)
}

func envStr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
func envBool(k string, def bool) (bool, error) {
	v := os.Getenv(k)
	if v == "" {
		return def, nil
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return false, fmt.Errorf("%s must be true or false: %w", k, err)
	}
	return b, nil
}
func envInt(k string, def int) (int, error) {
	v := os.Getenv(k)
	if v == "" {
		return def, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0, fmt.Errorf("%s must be an integer: %w", k, err)
	}
	return n, nil
}
func envFloat(k string, def float64) (float64, error) {
	v := os.Getenv(k)
	if v == "" {
		return def, nil
	}
	n, err := strconv.ParseFloat(v, 64)
	if err != nil {
		return 0, fmt.Errorf("%s must be a number: %w", k, err)
	}
	return n, nil
}
func envDur(k string, def time.Duration) (time.Duration, error) {
	v := os.Getenv(k)
	if v == "" {
		return def, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return 0, fmt.Errorf("%s must be a duration like 10m or 24h: %w", k, err)
	}
	return d, nil
}
