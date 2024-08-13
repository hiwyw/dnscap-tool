package app

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	_ "net/http/pprof"
	"sync"
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

const (
	snapshot_len = 1500

	promiscuous = true
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
		status: &runningStatus{
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
	status    *runningStatus
	finalizer func()
}

func (r *statusReporter) loop() {
	for {
		select {
		case <-r.ticker.C:
			r.status.RunningTime = time.Since(r.status.StartupTime).String()
			r.status.AvgEventRate = r.status.TotalEventCount / uint64(time.Since(r.status.StartupTime).Seconds())
			s, _ := json.Marshal(r.status)
			logger.Infof("running status: %s", string(s))
		case <-r.ctx.Done():
			r.finalizer()
			return
		}
	}
}

type runningStatus struct {
	StartupTime     time.Time `json:"startup_time"`
	RunningTime     string    `json:"running_time"`
	TotalEventCount uint64    `json:"total_event_count"`
	ErrEventCount   uint64    `json:"error_event_count"`
	AvgEventRate    uint64    `json:"avg_event_rate"`
	LatestEventTime time.Time `json:"latest_event_time"`
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
			a.reporter.status.TotalEventCount += 1
			a.reporter.status.LatestEventTime = e.EventTime
		case _, ok := <-a.source.ErrEvents():
			if !ok {
				a.Close()
				return
			}
			a.reporter.status.ErrEventCount += 1
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
