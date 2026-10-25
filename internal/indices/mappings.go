// Package indices owns mapping definitions and creation for every
// OpenSearch index Zemen writes to: the five from the proposal's data
// model (section 8) plus five supporting indices (context labels,
// detector snapshots, analyst dispositions, analyst feedback, forecasts).
package indices

import "encoding/json"

// Logical index names; Config.IndexName adds the environment prefix.
const (
	DetectorHealth   = "detector-health"
	ReplayCase       = "replay-case"
	DetectorLineage  = "detector-lineage"
	CalendarSignal   = "calendar-signal"
	DetectorDebt     = "detector-debt"
	FindingContext   = "finding-context"
	DetectorSnapshot = "detector-snapshot"
	Disposition      = "disposition"
	Feedback         = "feedback"
	Forecast         = "forecast"
)

// All lists every logical index in creation order.
var All = []string{
	DetectorHealth, ReplayCase, DetectorLineage, CalendarSignal, DetectorDebt,
	FindingContext, DetectorSnapshot, Disposition, Feedback, Forecast,
}

type fields map[string]string

func prop(spec string) map[string]any {
	switch spec {
	case "text":
		return map[string]any{"type": "text"}
	case "text:raw":
		return map[string]any{"type": "text", "fields": map[string]any{"raw": map[string]any{"type": "keyword"}}}
	case "text:store": // kept in _source only, never indexed (JSON blobs)
		return map[string]any{"type": "text", "index": false}
	case "date_range":
		return map[string]any{"type": "date_range", "format": "yyyy-MM-dd"}
	default:
		return map[string]any{"type": spec}
	}
}

func properties(f fields) map[string]any {
	p := map[string]any{}
	for k, v := range f {
		p[k] = prop(v)
	}
	return p
}

var defs = map[string]fields{
	DetectorHealth: {
		"detector_id": "keyword", "detector_name": "keyword", "detector_type": "keyword",
		"enabled": "boolean", "input_indices": "keyword",
		"last_fired_at": "date", "expected_cadence_hours": "float", "silence_threshold_hours": "float",
		"history_episodes": "integer", "cadence_basis": "keyword",
		"status": "keyword", "status_reason": "text",
		"fp_trend_score": "float", "fp_drift": "float", "fp_basis": "keyword",
		"findings_total": "integer", "findings_7d": "integer", "baseline_per_day": "float", "surge_ratio": "float",
		"mitre_techniques": "keyword", "suggested_techniques": "keyword", "suggestion_reasons": "text",
		"window_complete": "boolean", "created_at": "date", "updated_at": "date",
	},
	ReplayCase: {
		"case_id": "keyword", "technique_id": "keyword", "description": "text",
		"target_index": "keyword", "mapped_detectors": "keyword", "mapped_detector_ids": "keyword",
		"events_json": "text:store", "last_result_json": "text:store",
		"allow_production_index": "boolean", "last_overall": "keyword",
		"last_run_at": "date", "last_pass_at": "date", "source_file": "keyword",
		"created_at": "date", "updated_at": "date",
	},
	DetectorLineage: {
		"detector_id": "keyword", "change_id": "keyword", "changed_at": "date",
		"reason": "text", "trigger_event": "keyword", "author": "keyword",
		"kind": "keyword", "changed_fields": "keyword", "pending_reason": "boolean", "snapshot_hash": "keyword",
	},
	CalendarSignal: {
		"signal_id": "keyword", "name": "text:raw", "date_range": "date_range",
		"expected_effect": "keyword", "affected_scope": "keyword", "confidence": "float",
		"recurring": "boolean", "notes": "text",
		"kind": "keyword", "source": "keyword", "detector_id": "keyword",
		"hits": "integer", "trials": "integer", "confirms": "integer", "overrides": "integer",
		"approximate": "boolean", "updated_at": "date",
	},
	DetectorDebt: {
		"detector_id": "keyword", "debt_score": "float", "age_factor": "float", "fp_factor": "float",
		"coverage_factor": "float", "computed_at": "date",
		"detector_name": "keyword", "explanation": "text", "kind": "keyword", "date": "keyword",
		"detector_count": "integer",
	},
	FindingContext: {
		"detector_id": "keyword", "detector_name": "keyword", "date": "keyword", "ethiopian_date": "keyword",
		"count": "integer", "baseline_mean": "float", "baseline_std": "float", "threshold": "float",
		"ratio": "float", "baseline_days": "integer", "label": "keyword", "auto_label": "keyword",
		"matched_signals": "keyword", "confidence": "float", "reasoning": "text",
		"feedback": "keyword", "feedback_note": "text", "feedback_signal": "keyword", "feedback_at": "date",
		"updated_at": "date",
	},
	DetectorSnapshot: {
		"detector_id": "keyword", "hash": "keyword", "snapshot_json": "text:store",
		"last_status": "keyword", "updated_at": "date",
	},
	Disposition: {
		"finding_id": "keyword", "detector_id": "keyword", "verdict": "keyword",
		"note": "text", "at": "date",
	},
	Feedback: {
		"detector_id": "keyword", "signal_id": "keyword", "confirms": "integer",
		"overrides": "integer", "updated_at": "date",
	},
	Forecast: {
		"signal_id": "keyword", "name": "text:raw", "start": "keyword", "end": "keyword",
		"days_until": "integer", "effect": "keyword", "summary": "text",
		"recommendations_json": "text:store", "alerted_at": "date", "updated_at": "date",
	},
}

// Properties returns the {"properties":{...}} body used to extend an
// existing index.
func Properties(logical string) []byte {
	f, ok := defs[logical]
	if !ok {
		return nil
	}
	b, _ := json.Marshal(map[string]any{"properties": properties(f)})
	return b
}

// Mapping returns the full create-index body (settings + mappings).
func Mapping(logical string) []byte {
	f, ok := defs[logical]
	if !ok {
		return nil
	}
	b, _ := json.Marshal(map[string]any{
		"settings": map[string]any{"number_of_shards": 1, "number_of_replicas": 0},
		"mappings": map[string]any{"properties": properties(f)},
	})
	return b
}
