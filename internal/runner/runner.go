// Package runner is Zemen's in-process scheduler (no external job runner):
// it runs the full sync on an interval and Replay Court on its own, longer
// interval, and optionally serves the dashboard alongside.
package runner

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"zemen/internal/config"
	"zemen/internal/osclient"
	"zemen/internal/pipeline"
	"zemen/internal/replay"
	"zemen/internal/web"
)

func logf(format string, a ...any) {
	fmt.Printf("%s  %s\n", time.Now().Format("2006-01-02 15:04:05"), fmt.Sprintf(format, a...))
}

// Run blocks until ctx is cancelled.
func Run(ctx context.Context, c *osclient.Client, cfg config.Config, withUI bool) error {
	if withUI {
		srv := &http.Server{Addr: cfg.UIAddr, Handler: (&web.Server{Client: c, Cfg: cfg}).Handler(), ReadHeaderTimeout: 10 * time.Second}
		go func() {
			logf("dashboard listening on http://%s", cfg.UIAddr)
			if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				logf("dashboard stopped: %v", err)
			}
		}()
		go func() { <-ctx.Done(); _ = srv.Shutdown(context.Background()) }()
	}

	sync := func() {
		out, err := pipeline.Sync(c, cfg, time.Now())
		if err != nil {
			logf("sync failed: %v", err)
			return
		}
		logf("sync ok: %d detectors, %d/%d findings, debt %.1f, %d upcoming windows, %d warning(s)",
			len(out.Detectors), len(out.Findings.Findings), out.Findings.Total, out.Debt.SOC, len(out.Forecast), len(out.Warnings))
		for _, w := range out.Warnings {
			logf("warning: %s", w)
		}
		if out.Notified > 0 {
			logf("sent %d forecast notification(s)", out.Notified)
		}
	}
	doReplay := func() {
		if stored, err := replay.LoadStored(c, cfg); err != nil || len(stored) == 0 {
			return
		}
		logf("replay court: starting")
		outs, err := pipeline.RunReplay(c, cfg, "")
		if err != nil {
			logf("replay failed: %v", err)
			return
		}
		for _, o := range outs {
			logf("replay %s: %s", o.CaseID, o.Overall)
		}
	}

	logf("zemen running: sync every %s, replay every %s", cfg.SyncInterval, cfg.ReplayInterval)
	sync()
	syncT := time.NewTicker(cfg.SyncInterval)
	replayT := time.NewTicker(cfg.ReplayInterval)
	defer syncT.Stop()
	defer replayT.Stop()
	first := time.After(2 * time.Minute)
	for {
		select {
		case <-ctx.Done():
			logf("shutting down")
			return nil
		case <-syncT.C:
			sync()
		case <-replayT.C:
			doReplay()
		case <-first:
			doReplay()
		}
	}
}

// Serve runs only the dashboard.
func Serve(ctx context.Context, c *osclient.Client, cfg config.Config) error {
	srv := &http.Server{Addr: cfg.UIAddr, Handler: (&web.Server{Client: c, Cfg: cfg}).Handler(), ReadHeaderTimeout: 10 * time.Second}
	go func() { <-ctx.Done(); _ = srv.Shutdown(context.Background()) }()
	logf("dashboard on http://%s", cfg.UIAddr)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}
