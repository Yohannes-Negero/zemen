# Zemen (ዘመን)

Detection integrity and Ethiopian temporal context for OpenSearch and Wazuh.

## Demo video

[![Zemen demo video](https://img.youtube.com/vi/Ua2puabl500/maxresdefault.jpg)](https://youtu.be/Ua2puabl500?si=dnkRf3ArM2Zr7Jvy)

Watch the 5-minute demo: https://youtu.be/Ua2puabl500?si=dnkRf3ArM2Zr7Jvy

A walkthrough of every feature: detector health radar, Replay Court, ATT&CK coverage, Ethiopian calendar context, forecast, lineage and the detection debt score.

## Team SUKUNA
| Name | ID | 
|---|---|
| [Yohannes Negero] | [CTC-312-26] |


Zemen sits beside an existing OpenSearch Security Analytics deployment (Wazuh's indexer is OpenSearch, so it works there too). It does not replace your SIEM, add agents, or need new log sources. One Go binary, standard library only.

## What it does

| Module | What you get |
|---|---|
| Detector Health Radar | Learns each detector's normal cadence and flags `silent` ones; tracks false-positive drift; says honestly when it cannot tell (`no_data_in_window`) |
| Temporal Context Engine | Finds days a detector fired far above normal and explains them with the Ethiopian calendar (holidays, fasting seasons, pay windows) or a pattern learned from your own data, with a step-by-step reasoning chain |
| Replay Court | Replays recorded attack events into an index your detector watches and records a dated pass/fail for whether it really fires |
| Detector Lineage | Automatic biography per detector: first seen, definition changes (diffed), status changes, replay regressions, plus the reasons your team records |
| Detector Debt Score | 0-100 per detector and for the whole SOC, with the reasoning, tracked daily |
| Seasonal Risk Forecast | Upcoming windows with per-detector expected volume change and a one-time webhook notification |
| Federated Calendar Learning | Anonymized pattern signatures exchanged as files between institutions |
| ATT&CK coverage | Heatmap showing verified / healthy / degraded / uncovered techniques |

## Quick start (Windows PowerShell)

```powershell
$env:ZEMEN_OPENSEARCH_URL = "http://localhost:9200"
$env:ZEMEN_OPENSEARCH_USERNAME = "admin"
$env:ZEMEN_OPENSEARCH_PASSWORD = "your-password"

.\zemen.exe init            # creates .\zemen-data with editable templates
.\zemen.exe doctor          # checks connection, plugin, paging, indices
.\zemen.exe init-indices    # creates/extends Zemen's 10 indices (safe to repeat)
.\zemen.exe sync            # runs everything once
.\zemen.exe status
.\zemen.exe run             # keeps it running + dashboard at http://127.0.0.1:8080
```

Linux/macOS: same commands with `export VAR=value` and `./zemen-linux`.

If `doctor` says "server gave HTTP response to HTTPS client", use `http://`. For a self-signed `https://` certificate set `ZEMEN_OPENSEARCH_INSECURE_SKIP_VERIFY=true`.

## Daily use

```
zemen status                          health table with reasons
zemen anomalies -v --days 90          spike days, labeled, with reasoning
zemen feedback <detector> <date> confirm|override [--signal id]
zemen findings <detector> -n 5        newest findings with ids and times
zemen disposition <finding-id> tp|fp  teach it what is a false positive
zemen tags list | accept <det> | set <det> T1110,T1190
zemen coverage --html coverage.html
zemen replay load | run | list
zemen lineage show <det> | add <det> --reason "..." --trigger INC-12
zemen debt -v
zemen forecast
zemen calendar --days 120             offline: upcoming signals with Ethiopian dates
zemen federated export me.json | import peer1.json peer2.json | status
```

The dashboard has a tab for each of these, including guided ATT&CK tagging, replay-case upload with validation, and confirm/override buttons on anomalies.

## Making it yours (no code)

`zemen-data/calendar_custom.json` adds or replaces calendar signals: pay days, batch jobs, exam seasons. Kinds: `gregorian_range`, `gregorian_monthly`, `gregorian_annual`, `ethiopian_monthly`, `ethiopian_annual`. `disable_builtin` switches off built-ins. The file is validated with clear messages.

`zemen-data/replay_cases/*.json` holds Replay Court cases. Copy `TEMPLATE.json.example`, edit, rename to `.json`, run `zemen replay load`. A case is refused if its `target_index` is not watched by the mapped detector, if it is exactly the index the detector watches, or if its name does not contain `replay` (so replays can never be mixed into real logs unless a case sets `allow_production_index`).

For the full MITRE matrix: download `enterprise-attack.json` from github.com/mitre-attack/attack-stix-data and run `zemen attack-import enterprise-attack.json`. Tactics and their order are read from the bundle itself, so it follows MITRE's restructuring (current versions split Defense Evasion into Stealth and Defense Impairment); tested on the real 55 MB bundle (15 tactics, 259 techniques).

## Know these limits

These matter more than the feature list.

1. **Tested against a faithful mock, not a live cluster.** 107 end-to-end checks and 27 dashboard checks pass against `testutil/mockserver`, which reproduces the real findings structure and the 10,000-result window of a live OpenSearch (24,216 findings). `zemen doctor` and `zemen sync` also ran successfully against a real OpenSearch 3.5.0 cluster. Your cluster may differ. `zemen doctor` tests each assumption below and tells you.
2. **OpenSearch cannot page past 10,000 results in one listing** (default `max_result_window`; found on a real 24,216-finding cluster). When history is bigger, Zemen verifies the `detector_id` filter works and fetches each detector separately, recording per detector whether its history is complete. A detector with more than 10,000 findings uses its newest 10,000, which is what cadence and baselines need. If the filter cannot be verified, Zemen reports `TRUNCATED` and uses `no_data_in_window` instead of guessing. It never claims `never_fired` unless that detector's complete history was proven empty.
3. **Replay Court needs a setup step per detector**: the detector's input index pattern must be a wildcard (e.g. `postgres-logs*`) so a separate replay index (`postgres-logs-zemen-replay`) is watched too. Detectors run on their own schedule (often every minute), so a replay waits up to `ZEMEN_REPLAY_WAIT` (3 min). Pass means a finding referencing the replayed documents appeared. The optional workflow trigger (`ZEMEN_REPLAY_TRIGGER`) uses an Alerting endpoint that could not be verified here and is off by default.
4. **Default pay-cycle windows are assumptions** (government salary: Ethiopian day 25-30). Replace them with your real dates in `calendar_custom.json`. Pension disbursement ships as a disabled template for the same reason.
5. **Islamic dates are approximate** (arithmetic calendar, +-1-2 days vs moon sighting). Windows are padded and marked approximate.
6. **Calendar confidence starts as a prior and is learned locally.** With little history Zemen says so in the reasoning chain rather than sounding sure. Your confirm/override decisions change it.
7. **Noise detection without dispositions is a proxy** (volume vs the previous 8 weeks, ignoring calendar-explained days) and produces `noise_suspected`, never `noise_drowned`. Use `zemen disposition` to move to real false-positive rates.
8. **Federated learning is file-based.** There is no central server; it takes effect only when 2+ peers contributed a signal. Exports contain only quantized ratios-to-normal, never logs, detector names or counts. Review before sharing.
9. **The dashboard is built into the binary**, not an OpenSearch Dashboards plugin. All data also lives in the `zemen-*` indices, so you can build Dashboards visualizations on them.
10. **Dashboard security**: binds to 127.0.0.1 by default. If you expose it, set `ZEMEN_UI_TOKEN` and put it behind TLS.

## Where data goes

Ten indices (prefix `zemen-`): the five from the proposal (`detector-health`, `replay-case`, `detector-lineage`, `calendar-signal`, `detector-debt`) plus `finding-context`, `detector-snapshot`, `disposition`, `feedback`, `forecast`. `init-indices` is safe to re-run and extends indices created by older versions.

## Development

```
go build -o zemen ./cmd/zemen
go test ./...                     calendar, stats, validation unit tests
bash testutil/e2e.sh              107 end-to-end checks against the mock cluster
npm i jsdom && node testutil/ui_test.js   dashboard checks (needs zemen serve running)
GOOS=windows GOARCH=amd64 go build -o zemen.exe ./cmd/zemen
```

Layout: `cmd/zemen` CLI; `internal/{osclient,secanalytics,ethcal,stats,temporal,health,replay,lineage,debt,forecast,federated,attack,pipeline,runner,web}`; `testutil/` mock cluster and tests.
