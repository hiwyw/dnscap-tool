package app

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	_ "net/http/pprof"
	"sync"
	"sync/atomic"
	"time"

	"github.com/panjf2000/ants/v2"

	"github.com/hiwyw/dnscap-tool/app/config"
	"github.com/hiwyw/dnscap-tool/app/handler"
	"github.com/hiwyw/dnscap-tool/app/handler/dnsdb"
	"github.com/hiwyw/dnscap-tool/app/handler/dnslog"
	"github.com/hiwyw/dnscap-tool/app/handler/ipinfo"
	"github.com/hiwyw/dnscap-tool/app/handler/session"
	td "github.com/hiwyw/dnscap-tool/app/handler/trafficdirection"
	"github.com/hiwyw/dnscap-tool/app/handler/tunnelsec"
	"github.com/hiwyw/dnscap-tool/app/logger"
	"github.com/hiwyw/dnscap-tool/app/types"
)

func NewApp(cfg *config.Config) *App {
	a := &App{
		ctx:                context.Background(),
		wg:                 sync.WaitGroup{},
		cfg:                cfg,
		middlewareHandlers: []handler.MiddlewareHandler{},
		resultHandlers:     []handler.ResultHandler{},
		closeOnce:          sync.Once{},
	}

	pool, err := ants.NewPool(a.cfg.HandlerWorkerCount)
	if err != nil {
		logger.Fatal(err)
	}
	a.pool = pool

	if cfg.PprofEnable {
		go pprof(cfg.PprofHttpPort)
	}

	childCtx, cancel := context.WithCancel(a.ctx)
	a.cancel = cancel

	finalizer := func() {
		a.wg.Done()
	}

	switch a.cfg.InputType {
	case config.InputTypePcap:
		a.source = types.NewCaptureSource(childCtx, a.cfg.DecodeWorkerCount, a.cfg.Device, a.cfg.BpfFilter, finalizer)
		a.wg.Add(1)
	case config.InputTypePcapFile:
		a.source = types.NewFilesSource(childCtx, a.cfg.DecodeWorkerCount, a.cfg.PcapFiles, a.cfg.BpfFilter, finalizer)
		a.wg.Add(1)
	}

	for _, h := range a.cfg.MiddlewareHandlers {
		switch h {
		case config.SessionType:
			if a.cfg.SessionConfig.Enable {
				a.middlewareHandlers = append(
					a.middlewareHandlers,
					session.NewHandler(
						childCtx,
						a.cfg.SessionConfig.SessionCacheSize))
				logger.Warnf("when session handler enabled, dns events cannot be processed in parallel， so will reset worker count to 1")
				a.source.SetWorkerCount(1)
				a.pool.Tune(1)

			}
		case config.IpInfoType:
			if a.cfg.IpInfoConfig.Enable {
				a.middlewareHandlers = append(
					a.middlewareHandlers,
					ipinfo.NewHandler(
						childCtx,
						a.cfg.IpInfoConfig.GeoIPFilename))
			}
		case config.TunnelSecType:
			if a.cfg.TunnelSecConfig.Enable {
				a.middlewareHandlers = append(
					a.middlewareHandlers,
					tunnelsec.NewHandler(
						childCtx,
						a.cfg.TunnelSecConfig.SpecialTlds,
						a.cfg.TunnelSecConfig.EnableSubdomainEntropy,
						a.cfg.TunnelSecConfig.EnableSubdomainEncodingDetect,
						a.cfg.TunnelSecConfig.EncodingDetectLeastLabelLength))
			}
		case config.TrafficDirectionType:
			if a.cfg.TrafficDirectionConfig.Enable {
				a.middlewareHandlers = append(
					a.middlewareHandlers,
					td.NewHandler(
						childCtx,
						a.cfg.TrafficDirectionConfig.SelfIps))
			}
		}
	}

	for _, h2 := range a.cfg.ResultHandlers {
		switch h2 {
		case config.DnsLogWriterType:
			if a.cfg.DnslogConfig.Enable {
				a.resultHandlers = append(
					a.resultHandlers,
					dnslog.NewHandler(
						childCtx,
						a.cfg.DnslogConfig.Filename,
						a.cfg.DnslogConfig.MaxFileSize,
						a.cfg.DnslogConfig.MaxFileCount,
						a.cfg.DnslogConfig.MaxFileAge,
						string(a.cfg.DnslogConfig.Format),
						finalizer))
				a.wg.Add(1)
			}
		case config.DbWriterType:
			if a.cfg.DnsdbConfig.Enable {
				d, err := time.ParseDuration(a.cfg.DnsdbConfig.MaxRollingInterval)
				if err != nil {
					logger.Fatal(err)
				}
				a.resultHandlers = append(
					a.resultHandlers,
					dnsdb.NewHandler(
						childCtx,
						a.cfg.DnsdbConfig.Filename,
						a.cfg.DnsdbConfig.MaxFileRowCount,
						d,
						a.cfg.DnsdbConfig.MaxFileCount,
						finalizer))
				a.wg.Add(1)
			}
		}
	}

	if len(a.resultHandlers) < 1 {
		logger.Fatalf("should at least one result handler")
	}

	statusTickerDuration, err := time.ParseDuration(a.cfg.StatusReportInterval)
	if err != nil {
		logger.Fatal(err)
	}
	reporter := newReporter(childCtx, statusTickerDuration, finalizer)
	a.reporter = reporter
	a.wg.Add(1)

	return a
}

func pprof(port int) {
	http.ListenAndServe(fmt.Sprintf("0.0.0.0:%d", port), nil)
}

type App struct {
	ctx                context.Context
	wg                 sync.WaitGroup
	cfg                *config.Config
	source             types.EventSource
	middlewareHandlers []handler.MiddlewareHandler
	resultHandlers     []handler.ResultHandler
	cancel             func()
	pool               *ants.Pool
	reporter           *statusReporter
	closeOnce          sync.Once
}

func newReporter(ctx context.Context, statDuration time.Duration, finalizer func()) *statusReporter {
	r := &statusReporter{
		ctx:    ctx,
		ticker: *time.NewTicker(statDuration),
		status: &runningState{
			StartupTime: time.Now(),
		},
		finalizer: finalizer,
	}
	go r.loop()
	return r
}

type statusReporter struct {
	ctx       context.Context
	ticker    time.Ticker
	status    *runningState
	finalizer func()
}

func (r *statusReporter) loop() {
	for {
		select {
		case <-r.ticker.C:
			s := map[string]interface{}{
				"startup_time":      r.status.StartupTime,
				"running_time":      time.Since(r.status.StartupTime).String(),
				"total_event_count": r.status.TotalEventCount.Load(),
				"error_event_count": r.status.ErrEventCount.Load(),
				"avg_event_rate":    r.status.TotalEventCount.Load() / uint64(time.Since(r.status.StartupTime).Seconds()),
				"latest_event_time": r.status.LatestEventTime.Load().(time.Time),
			}
			ss, _ := json.Marshal(s)
			logger.Infof("running status: %s", string(ss))
		case <-r.ctx.Done():
			r.finalizer()
			return
		}
	}
}

func (r *statusReporter) CountEvent() {
	r.status.TotalEventCount.Add(1)
}

func (r *statusReporter) CountErrEvent() {
	r.status.ErrEventCount.Add(1)
}

func (r *statusReporter) UpdateLastEventTime(t time.Time) {
	r.status.LatestEventTime.Store(t)
}

type runningState struct {
	StartupTime     time.Time     `json:"startup_time"`
	TotalEventCount atomic.Uint64 `json:"total_event_count"`
	ErrEventCount   atomic.Uint64 `json:"error_event_count"`
	LatestEventTime atomic.Value  `json:"latest_event_time"`
}

func (a *App) Run() {
	logger.Info("app running")
	for {
		select {
		case e, ok := <-a.source.Events():
			if !ok {
				a.Close()
				return
			}
			a.pool.Submit(func() {
				for _, h1 := range a.middlewareHandlers {
					e = h1.Handle(e)
				}

				for _, h2 := range a.resultHandlers {
					h2.Handle(e)
				}
			})
			a.reporter.CountEvent()
			a.reporter.UpdateLastEventTime(e.EventTime)
		case _, ok := <-a.source.ErrEvents():
			if !ok {
				a.Close()
				return
			}
			a.reporter.CountErrEvent()
		}
	}
}

func (a *App) Close() {
	a.closeOnce.Do(func() {
		if err := a.pool.ReleaseTimeout(time.Second * 3); err != nil {
			logger.Errorf("app handler worker pool release timeout %s", err)
		}
		a.cancel()
		logger.Infof("app groutinue will exit after all handler exited")
		logger.Infof("waitting handlers")
		a.wg.Wait()
		logger.Infof("all handlers exited, app exiting")
	})
}
