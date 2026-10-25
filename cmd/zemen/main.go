// Command zemen is a detection-integrity and Ethiopian temporal-context
// layer for OpenSearch / Wazuh security operations. See README.md.
package main

import (
	"fmt"
	"os"
	"strings"

	"zemen/internal/config"
	"zemen/internal/osclient"
)

const version = "1.0.0"

// env is what online commands receive.
type env struct {
	cfg    config.Config
	client *osclient.Client
}

type command struct {
	name, summary string
	offline       bool // does not need a cluster
	run           func(e *env, args []string) error
}

var commands []command

func init() {
	commands = []command{
		{"init", "create the zemen-data folder with editable templates", true, cmdInit},
		{"doctor", "check cluster connection, plugin, indices and configuration", false, cmdDoctor},
		{"init-indices", "create/extend Zemen's OpenSearch indices", false, cmdInitIndices},
		{"sync", "run the full pipeline: health, calendar context, lineage, debt, forecast", false, cmdSync},
		{"status", "detector health table", false, cmdStatus},
		{"coverage", "ATT&CK coverage heatmap  (--html file.html)", false, cmdCoverage},
		{"tags", "ATT&CK tagging: list | set | accept | export | import", false, cmdTags},
		{"anomalies", "spike days with calendar explanations  (--days N, -v)", false, cmdAnomalies},
		{"findings", "list a detector's newest findings with ids: findings <detector> [-n 5] [--date yyyy-mm-dd]", false, cmdFindings},
		{"explain", "explain a finding's day: explain <finding-id>", false, cmdExplain},
		{"feedback", "confirm/override an explanation: feedback <detector> <date> confirm|override", false, cmdFeedback},
		{"disposition", "mark a finding true/false positive: disposition <finding-id> tp|fp", false, cmdDisposition},
		{"replay", "Replay Court: template | load | list | run [case]", false, cmdReplay},
		{"lineage", "detector biography: show <detector> | add <detector> --reason ...", false, cmdLineage},
		{"debt", "detection debt score per detector and for the SOC", false, cmdDebt},
		{"forecast", "upcoming high-noise windows with recommendations", false, cmdForecast},
		{"federated", "share/import anonymized calendar patterns: export | import | status", false, cmdFederated},
		{"calendar", "print upcoming Ethiopian calendar signals (offline)  (--days N)", true, cmdCalendar},
		{"attack-import", "load the full MITRE ATT&CK matrix: attack-import <enterprise-attack.json>", true, cmdAttackImport},
		{"run", "run continuously: scheduled sync + replay + dashboard  (--no-ui)", false, cmdRun},
		{"serve", "run only the dashboard", false, cmdServe},
	}
}

func usage() {
	fmt.Printf("zemen %s - detection integrity and Ethiopian temporal context for OpenSearch/Wazuh\n\nUsage: zemen <command> [args]\n\nCommands:\n", version)
	for _, c := range commands {
		fmt.Printf("  %-14s %s\n", c.name, c.summary)
	}
	fmt.Print(`
Configuration (environment variables):
  ZEMEN_OPENSEARCH_URL                   required, e.g. http://localhost:9200
  ZEMEN_OPENSEARCH_USERNAME / _PASSWORD  basic auth (or ZEMEN_OPENSEARCH_API_KEY)
  ZEMEN_OPENSEARCH_INSECURE_SKIP_VERIFY  true for self-signed certificates
  ZEMEN_DATA_DIR                         default zemen-data
  ZEMEN_TZ_OFFSET_HOURS                  default 3 (Ethiopia)
  ZEMEN_SYNC_INTERVAL / _REPLAY_INTERVAL default 10m / 24h
  ZEMEN_UI_ADDR / ZEMEN_UI_TOKEN         default 127.0.0.1:8080 / none
  ZEMEN_WEBHOOK_URL                      forecast notifications
Full list and guidance: README.md
`)
}

func main() {
	if len(os.Args) < 2 || os.Args[1] == "help" || os.Args[1] == "-h" || os.Args[1] == "--help" {
		usage()
		return
	}
	if os.Args[1] == "version" || os.Args[1] == "--version" {
		fmt.Println("zemen", version)
		return
	}
	var cmd *command
	for i := range commands {
		if commands[i].name == os.Args[1] {
			cmd = &commands[i]
		}
	}
	if cmd == nil {
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
	var e env
	var err error
	if cmd.offline {
		e.cfg, err = config.LoadOffline()
	} else {
		e.cfg, err = config.Load()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "configuration error:", err)
		os.Exit(1)
	}
	if !cmd.offline {
		e.client = osclient.New(e.cfg)
	}
	if err := cmd.run(&e, os.Args[2:]); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func trunc(s string, n int) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "..."
}
