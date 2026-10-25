#!/usr/bin/env bash
# End-to-end test: builds Zemen and the mock cluster, runs every module against
# it, and asserts on results. Usage: bash testutil/e2e.sh
set -u
cd "$(dirname "$0")/.."
ROOT=$(pwd)
BIN=$(mktemp -d)   # build somewhere executable (some mounts are noexec)
go build -o "$BIN/zemen" ./cmd/zemen || exit 1
go build -o "$BIN/mockserver" ./testutil/mockserver || exit 1

WORK=$(mktemp -d)
export ZEMEN_OPENSEARCH_URL=http://127.0.0.1:9201
export ZEMEN_DATA_DIR=$WORK/data
export ZEMEN_REPLAY_POLL_INTERVAL=1s ZEMEN_REPLAY_WAIT=15s
export ZEMEN_UI_ADDR=127.0.0.1:18080
export ZEMEN_WEBHOOK_URL=http://127.0.0.1:9201/_hook
export ZEMEN_FORECAST_LEAD_DAYS=400
Z=$BIN/zemen
PASS=0; FAIL=0
ok()   { PASS=$((PASS+1)); echo "  PASS  $1"; }
bad()  { FAIL=$((FAIL+1)); echo "  FAIL  $1"; }
has()  { if grep -qE -- "$2" <<<"$3"; then ok "$1"; else bad "$1  (wanted /$2/)"; echo "-----"; echo "$3" | head -30; echo "-----"; fi; }
hasnt(){ if grep -qE -- "$2" <<<"$3"; then bad "$1  (did not want /$2/)"; else ok "$1"; fi; }

"$BIN/mockserver" > "$WORK/mock.log" 2>&1 &
MP=$!
trap 'kill $MP 2>/dev/null; kill ${UP:-} 2>/dev/null' EXIT
for i in $(seq 1 30); do curl -s localhost:9201 >/dev/null 2>&1 && break; sleep 0.3; done

echo "== setup"
out=$($Z init 2>&1);                  has "init creates data dir" "calendar_custom.json" "$out"
out=$($Z doctor 2>&1);                has "doctor connects" "\[ ok \] connect" "$out"
has "doctor sees detectors" "8 detector" "$out"
has "doctor sees findings API" "findings API" "$out"
out=$($Z init-indices 2>&1);          has "init-indices creates 10 indices" "zemen-forecast +created" "$out"
out=$($Z init-indices 2>&1);          has "init-indices idempotent" "exists, fields up to date" "$out"

echo "== sync (health, temporal, lineage, debt, forecast)"
out=$($Z sync 2>&1); echo "$out"
has "sync reports complete history" "complete history" "$out"
has "sync fetches per detector past the 10,000 window" "fetched per detector" "$out"
has "sync labels spikes" "Spike days" "$out"
st=$($Z status 2>&1)
has "legacy detector is silent"   "legacy-windows-detector +silent" "$st"
has "never-fired confirmed"       "never-fired-detector +never_fired" "$st"
has "disabled detector"           "disabled-detector +disabled" "$st"
has "network surge is noise_suspected" "network-event-detector +noise_suspected" "$st"
has "fim detector healthy"        "fim-event-detector +healthy" "$st"
has "learned cadence used"        "learned" "$st"

echo "== temporal context"
an=$($Z anomalies --days 400 -v 2>&1)
has "calendar-explained spike" "expected_local_pattern" "$an"
has "learned org overlay (day-15 batch job)" "expected_org_pattern" "$an"
has "unexplained spike escalated" "unexplained_escalate" "$an"
has "reasoning chain shows history" "History:" "$an"
has "reasoning chain shows confidence formula" "Confidence [0-9.]+ = " "$an"

echo "== tagging"
tg=$($Z tags list 2>&1)
has "suggests T1110 for brute force" "suggested: T1110" "$tg"
has "suggests T1003 from sigma tag"  "suggested: T1003" "$tg"
out=$($Z tags accept POSTGRES-BRUTE 2>&1); has "accept suggestion" "now claims: T1110" "$out"
out=$($Z tags set fim-event-detector T1565,T1070.002 2>&1); has "set tags incl subtechnique" "T1070.002" "$out"
out=$($Z tags set fim-event-detector TXXXX 2>&1);          has "rejects invalid technique" "not a valid ATT&CK" "$out"
out=$($Z tags set fim-event-detector T9999 2>&1);          has "rejects unknown technique" "not in the loaded ATT&CK matrix" "$out"
cov=$($Z coverage --html "$WORK/cov.html" 2>&1)
has "coverage heatmap rendered" "\[h\] T1110" "$cov"
has "coverage lists uncovered" "\[ \] T1486" "$cov"
[ -s "$WORK/cov.html" ] && ok "coverage html written" || bad "coverage html written"

echo "== replay court"
tpl=$($Z replay template); has "template prints" "target_index" "$tpl"
mkdir -p "$ZEMEN_DATA_DIR/replay_cases"
cat > "$ZEMEN_DATA_DIR/replay_cases/good.json" <<'JSON'
[
 {"case_id":"sqli","technique_id":"T1190","description":"tautology","target_index":"postgres-logs-zemen-replay",
  "mapped_detectors":["POSTGRES-SQLI"],"events":[{"@timestamp":"{{now}}","message":"statement: select * from a where id=1 OR 1=1"}]},
 {"case_id":"brute","technique_id":"T1110","description":"auth failures","target_index":"postgres-logs-zemen-replay",
  "mapped_detectors":["POSTGRES-BRUTE"],"events":[{"@timestamp":"{{now}}","message":"FATAL: password authentication failed for user x"}]},
 {"case_id":"legacy-cred","technique_id":"T1003","description":"should FAIL: detector is dead","target_index":"winlogbeat-zemen-replay",
  "mapped_detectors":["legacy-windows-detector"],"events":[{"@timestamp":"{{now}}","message":"mimikatz sekurlsa"}]}
]
JSON
cat > "$ZEMEN_DATA_DIR/replay_cases/unsafe.json" <<'JSON'
{"case_id":"unsafe","technique_id":"T1565","target_index":"prod-exact","mapped_detectors":["exact-index-detector"],"events":[{"message":"x"}]}
JSON
cat > "$ZEMEN_DATA_DIR/replay_cases/wrongindex.json" <<'JSON'
{"case_id":"wrongindex","technique_id":"T1110","target_index":"unrelated-index","mapped_detectors":["POSTGRES-BRUTE"],"events":[{"message":"x"}]}
JSON
out=$($Z replay load 2>&1); echo "$out"
has "loads valid cases" "Loaded 3 case" "$out"
has "refuses production-index replay" "mixed into real logs" "$out"
has "refuses non-matching index" "does not include target_index" "$out"
out=$($Z replay run 2>&1); rc=$?; echo "$out"
has "sqli passes"   "PASS +POSTGRES-SQLI fired" "$out"
has "brute passes"  "PASS +POSTGRES-BRUTE fired" "$out"
has "dead detector fails replay" "FAIL +legacy-windows-detector" "$out"
[ $rc -ne 0 ] && ok "replay run exits non-zero on failure" || bad "replay run exits non-zero on failure"
out=$($Z replay run sqli 2>&1); has "single case run" "sqli: PASS" "$out"

echo "== lineage, debt, forecast"
$Z sync >/dev/null 2>&1
ln=$($Z lineage show legacy-windows-detector 2>&1); echo "$ln"
has "lineage records first seen" "auto-first-seen" "$ln"
has "lineage records replay failure" "auto-replay-failed" "$ln"
out=$($Z lineage add legacy-windows-detector --reason "Retired agent; rule kept for audit" --trigger INC-7 --author yohannes 2>&1)
has "manual lineage entry" "Recorded" "$out"
has "biography shows manual entry" "Retired agent" "$($Z lineage show legacy-windows-detector 2>&1)"
db=$($Z debt -v 2>&1); echo "$db" | head -12
has "debt shows SOC score" "SOC detection debt: [0-9.]+" "$db"
has "debt explains replay-verified age" "Last passed a replay" "$db"
has "debt explains unmapped detector" "No Replay Court case is mapped" "$db"
fc=$($Z forecast 2>&1)
has "forecast has windows" "Meskel|Enkutatash|Timkat|Genna|Fasika|Ramadan|salary" "$fc"
has "forecast gives learned recommendations" "Expect about" "$fc"
hooks=$(curl -s localhost:9201/_hook/count); has "webhook notified" '"count":[1-9]' "$hooks"
hooks2a=$(curl -s localhost:9201/_hook/count); $Z sync >/dev/null 2>&1; hooks2b=$(curl -s localhost:9201/_hook/count)
[ "$hooks2a" = "$hooks2b" ] && ok "webhook fires once per window (no repeats)" || bad "webhook repeats: $hooks2a -> $hooks2b"

echo "== feedback + dispositions"
det=fim-event-detector
day=$(echo "$an" | grep unexplained_escalate | grep fim-event | head -1 | awk '{print $1}')
if [ -n "$day" ]; then
  out=$($Z feedback $det "$day" override --signal gov-salary --note "month-end reconciliation" 2>&1); has "override with signal" "expected_local_pattern" "$out"
  $Z sync >/dev/null 2>&1
  an2=$($Z anomalies --days 400 -v 2>&1)
  has "override persists across sync" "Analyst override" "$an2"
else bad "found an unexplained fim day to override"; fi
dayx=$(echo "$an" | grep expected_local_pattern | grep fim-event | head -1 | awk '{print $1}')
if [ -n "$dayx" ]; then out=$($Z feedback $det "$dayx" confirm --note ok 2>&1); has "confirm" "confirmed" "$out"; fi
out=$($Z feedback $det 2020-01-01 confirm 2>&1); has "feedback on unknown day is a clear error" "no anomaly context" "$out"
fid=$(curl -s "localhost:9201/_plugins/_security_analytics/findings/_search?sortOrder=desc&size=1" | sed -E 's/.*"id":"(f-[0-9]+)".*/\1/')
out=$($Z disposition "$fid" fp --note noisy 2>&1); has "disposition recorded" "Recorded" "$out"
out=$($Z disposition "$fid" maybe 2>&1);          has "bad verdict rejected" "verdict must be tp" "$out"
ex=$($Z explain "$fid" 2>&1); has "explain a finding" "Finding f-" "$ex"

echo "== lineage catches a detector edit"
curl -s -X POST localhost:9201/_mock/edit_detector >/dev/null
$Z sync >/dev/null 2>&1
ln=$($Z lineage show POSTGRES-SQLI 2>&1); echo "$ln"
has "definition change detected automatically" "auto-definition-change" "$ln"
has "names the field that changed" "inputs\[0\]\.detector_input\.indices" "$ln"
has "warns nobody explained it" "no recorded reason" "$ln"
$Z lineage add POSTGRES-SQLI --reason "Added the extra index for the new app" --trigger CHG-5 --author tester >/dev/null 2>&1
ln=$($Z lineage show POSTGRES-SQLI 2>&1)
hasnt "warning clears once a human explains it" "have no recorded reason" "$ln"
$Z sync >/dev/null 2>&1; $Z sync >/dev/null 2>&1
n=$($Z lineage show POSTGRES-SQLI 2>&1 | grep -c "auto-definition-change"); [ "$n" = "1" ] && ok "repeated syncs do not duplicate the change entry" || bad "definition change recorded $n times"
n=$($Z lineage show POSTGRES-SQLI 2>&1 | grep -c "auto-first-seen"); [ "$n" = "1" ] && ok "first-seen recorded exactly once" || bad "first-seen recorded $n times"

echo "== analyst verdicts drive false-positive tracking"
ids=$(curl -s "localhost:9201/_plugins/_security_analytics/findings/_search?detector_id=det-fim&sortOrder=desc&size=12" | grep -o '"id":"f-[0-9]*"' | sed -E 's/"id":"(f-[0-9]+)"/\1/' | head -12)
for f in $ids; do $Z disposition "$f" fp >/dev/null 2>&1; done
$Z sync >/dev/null 2>&1
st=$($Z status 2>&1)
has "12 false-positive verdicts make the detector noise_drowned" "fim-event-detector +noise_drowned" "$st"
has "status says it is based on analyst dispositions" "dispositions" "$st"

echo "== tagging without proof raises debt"
db=$($Z debt -v 2>&1)
has "tagged but unproven detector explains its coverage debt" "Claims 2 technique\(s\); 0 verified" "$db"

fl=$($Z findings fim-event-detector -n 3 2>&1); has "findings command lists ids with UTC and local time" "f-[0-9]+ +20[0-9-]+ [0-9:]+ +20[0-9-]+ [0-9:]+" "$fl"
[ "$(echo "$fl" | grep -c "f-")" = "3" ] && ok "findings -n 3 shows exactly 3" || bad "findings -n 3 count"
echo "== federated"
out=$($Z federated export "$WORK/me.json" 2>&1); has "federated export" "anonymized signal shape" "$out"
hasnt "export has no detector names" "fim-event|POSTGRES|network-event" "$(cat $WORK/me.json)"
hasnt "export has no raw counts field" "\"count\"" "$(cat $WORK/me.json)"
out=$($Z federated import "$WORK/me.json" 2>&1); has "refuses importing own export" "own export" "$out"
python3 - "$WORK" <<'PY'
import json,sys
w=sys.argv[1]; me=json.load(open(w+"/me.json"))
for i in (1,2):
    p=dict(me); p["org_pseudonym"]="peer%d"%i; open("%s/peer%d.json"%(w,i),"w").write(json.dumps(p))
PY
out=$($Z federated import "$WORK/peer1.json" "$WORK/peer2.json" 2>&1); has "imports peers" "Merged 2 peer" "$out"
has "federated status" "consensus strength" "$($Z federated status 2>&1)"
$Z sync >/dev/null 2>&1; has "sync notes federated prior" "federated consensus" "$($Z anomalies --days 400 -v 2>&1)"

echo "== custom calendar (self-service)"
cat > "$ZEMEN_DATA_DIR/calendar_custom.json" <<'JSON'
{"disable_builtin":["gov-salary"],"signals":[{"id":"bank-batch","name":"Month-end batch","kind":"gregorian_monthly","effect":"volume_spike","confidence":0.6,"day_from":28,"day_to":31}]}
JSON
cal=$($Z calendar --days 60 2>&1); has "custom signal appears" "Month-end batch" "$cal"; hasnt "disabled built-in gone" "Government salary" "$cal"
echo '{"signals":[{"id":"","kind":"nope","effect":"x"}]}' > "$ZEMEN_DATA_DIR/calendar_custom.json"
out=$($Z calendar 2>&1); has "invalid custom file gives clear errors" "id and name are required|unknown kind" "$out"
nday=$(echo "$an" | grep unexplained_escalate | grep network-event | head -1 | awk '{print $1}')
if [ -n "$nday" ]; then
  cat > "$ZEMEN_DATA_DIR/calendar_custom.json" <<JSON
{"signals":[{"id":"planned-load-test","name":"Planned load test","kind":"gregorian_range","effect":"volume_spike","confidence":0.8,"start":"$nday","end":"$nday"}]}
JSON
  $Z sync >/dev/null 2>&1
  an3=$($Z anomalies --days 400 -v 2>&1)
  has "a custom window you define explains the spike" "$nday.*network-event-detector.*expected_local_pattern" "$an3"
  has "reasoning cites your custom signal" "Planned load test" "$an3"
  has "reasoning names the source as custom" "source: custom" "$an3"
else bad "found an unexplained network day for the custom-window test"; fi
echo '{}' > "$ZEMEN_DATA_DIR/calendar_custom.json"

echo "== dashboard API"
$Z serve > "$WORK/serve.log" 2>&1 & UP=$!
for i in $(seq 1 30); do curl -s localhost:18080/ >/dev/null 2>&1 && break; sleep 0.3; done
api() { curl -s -H "X-Zemen-UI: 1" "$@"; }
has "UI page served" "<title>Zemen" "$(curl -s localhost:18080/)"
has "api/overview" '"detectors":8' "$(api localhost:18080/api/overview)"
has "api/health" "detector_name" "$(api localhost:18080/api/health)"
has "api/coverage" '"columns"' "$(api localhost:18080/api/coverage)"
has "api/contexts" '"reasoning"' "$(api localhost:18080/api/contexts)"
has "api/replay" '"case_id"' "$(api localhost:18080/api/replay)"
has "api/debt" '"rows"' "$(api localhost:18080/api/debt)"
has "api/forecast" '"recommendations"' "$(api localhost:18080/api/forecast)"
has "api/calendar" '"ethiopian_start"' "$(api 'localhost:18080/api/calendar?days=100')"
has "api/lineage" '"biography"' "$(api 'localhost:18080/api/lineage?detector=POSTGRES-BRUTE')"
has "api/tags set" '"mitre_techniques"' "$(api -X POST -d '{"detector_id":"det-pg-sqli","techniques":["T1190"]}' localhost:18080/api/tags)"
has "api/tags rejects bad id" '"error"' "$(api -X POST -d '{"detector_id":"det-pg-sqli","techniques":["nope"]}' localhost:18080/api/tags)"
has "POST without X-Zemen-UI header is refused (CSRF guard)" "missing X-Zemen-UI" "$(curl -s -X POST -d '{}' localhost:18080/api/sync)"
has "api/replay/case validates" '"error"' "$(api -X POST -d '{"case_id":"x","events":[{"a":1}],"target_index":"zzz","mapped_detectors":["POSTGRES-BRUTE"]}' localhost:18080/api/replay/case)"
has "api/sync" '"status_counts"' "$(api -X POST -d '{}' localhost:18080/api/sync)"
kill $UP 2>/dev/null; UP=
export ZEMEN_UI_TOKEN=secret
$Z serve > "$WORK/serve2.log" 2>&1 & UP=$!
for i in $(seq 1 30); do curl -s localhost:18080/ >/dev/null 2>&1 && break; sleep 0.3; done
has "token required when set" "missing or wrong token" "$(api localhost:18080/api/health)"
has "token accepted" "detector_name" "$(api -H 'X-Zemen-Token: secret' localhost:18080/api/health)"
kill $UP 2>/dev/null; UP=; unset ZEMEN_UI_TOKEN

echo "== resilience: cluster without startIndex / detector filter support"
kill $MP; sleep 0.5
MOCK_IGNORE_STARTINDEX=1 MOCK_IGNORE_DETECTOR_FILTER=1 "$BIN/mockserver" > "$WORK/mock2.log" 2>&1 & MP=$!
for i in $(seq 1 30); do curl -s localhost:9201 >/dev/null 2>&1 && break; sleep 0.3; done
$Z init-indices >/dev/null 2>&1
out=$($Z sync 2>&1); echo "$out" | head -4
has "reports truncation honestly" "TRUNCATED" "$out"
st=$($Z status 2>&1)
hasnt "never claims never_fired on truncated history" "never-fired-detector +never_fired" "$st"
has "uses no_data_in_window when unsure" "no_data_in_window" "$st"

echo "== one detector larger than the 10,000 window (like a real busy detector)"
kill $MP; sleep 0.5
MOCK_BIG_NET=1 "$BIN/mockserver" > "$WORK/mock3.log" 2>&1 & MP=$!
for i in $(seq 1 30); do curl -s localhost:9201 >/dev/null 2>&1 && break; sleep 0.3; done
$Z init-indices >/dev/null 2>&1
out=$($Z sync 2>&1); echo "$out" | head -5
has "caps the busy detector at its newest 10,000" "History capped at the newest 10,000 findings for: network-event-detector" "$out"
hasnt "does not call this truncated/unverifiable" "could not be verified" "$out"
hasnt "does not claim a full complete-history for a capped detector" "complete history" "$out"
has "other detectors still fully fetched" "per-detector history" "$out"
st=$($Z status 2>&1)
has "busy detector still gets a real status" "network-event-detector +(healthy|noise_suspected)" "$st"
has "never_fired still proven for a detector with an empty verified history" "never-fired-detector +never_fired" "$st"
out=$($Z anomalies --days 400 2>&1); hasnt "no misleading 0.0x" "\(0\.0x\)" "$out"

echo
echo "RESULT: $PASS passed, $FAIL failed"
rm -rf "$WORK"
[ $FAIL -eq 0 ]
