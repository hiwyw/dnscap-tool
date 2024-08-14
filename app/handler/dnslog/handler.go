package dnslog

import (
	"bufio"
	"context"
	"encoding/csv"
	"time"

	"github.com/natefinch/lumberjack"

	"github.com/hiwyw/dnscap-tool/app/logger"
	"github.com/hiwyw/dnscap-tool/app/types"
)

const (
	batchWriteTimeout = time.Second * 3

	recviceBufferLength = 10
	writerBuffSize      = 1024 * 8
)

type LogHandler struct {
	ctx           context.Context
	finalizer     func()
	writer        *lumberjack.Logger
	buffer        *bufio.Writer
	ch            chan string
	csvCh         chan []string
	lastFlushTime time.Time
	format        string
	csvWriter     *csv.Writer
}

func NewHandler(ctx context.Context, filename string, maxsize, fileCount, fileAge int, format string, finalizer func()) *LogHandler {
	h := &LogHandler{
		ctx:       ctx,
		finalizer: finalizer,
		writer: &lumberjack.Logger{
			Filename:   filename,
			MaxSize:    maxsize,
			MaxBackups: fileCount,
			MaxAge:     fileAge,
			Compress:   true,
		},
		format: format,
	}
	switch format {
	case "json":
		h.ch = make(chan string, recviceBufferLength)
		h.buffer = bufio.NewWriterSize(h.writer, writerBuffSize)
	case "csv":
		h.csvCh = make(chan []string, recviceBufferLength)
		h.csvWriter = csv.NewWriter(h.writer)
	}

	go h.loop()
	return h
}

func (h *LogHandler) loop() {
	if h.format == "json" {
		for {
			select {
			case s, ok := <-h.ch:
				if !ok {
					h.flush()
					logger.Infof("dnslog handler exiting")
					return
				}
				h.writeStr(s)
			case <-h.ctx.Done():
				h.flush()
				close(h.ch)
				logger.Infof("dnslog handler exiting by recvice signal")
				h.finalizer()
				logger.Infof("dnslog handler finalizer succeed")
				return
			}
		}
	}
	if h.format == "csv" {
		for {
			select {
			case s, ok := <-h.csvCh:
				if !ok {
					h.csvWriter.Flush()
					logger.Infof("dnslog handler exiting")
					return
				}
				h.writeCsv(s)
			case <-h.ctx.Done():
				h.csvWriter.Flush()
				close(h.csvCh)
				logger.Infof("dnslog handler exiting by recvice signal")
				h.finalizer()
				logger.Infof("dnslog handler finalizer succeed")
				return
			}
		}
	}
	logger.Fatalf("unknown format: %s", h.format)
}

func (h *LogHandler) Handle(e *types.DnsEvent) {
	switch h.format {
	case "json":
		h.ch <- e.JsonString() + "\n"
	case "csv":
		h.csvCh <- e.CsvStrings()
	default:
		logger.Fatalf("unknown format: %s", h.format)
	}
}

func (h *LogHandler) writeCsv(ss []string) {
	if err := h.csvWriter.Write(ss); err != nil {
		logger.Fatal(err)
	}
}

func (h *LogHandler) writeStr(s string) {
	if _, err := h.buffer.WriteString(s); err != nil {
		logger.Fatal(err)
	}

	if h.buffer.Available() < 1024*2 {
		h.flush()
	}

	if time.Since(h.lastFlushTime) > batchWriteTimeout {
		h.flush()
	}
}

func (h *LogHandler) flush() {
	if err := h.buffer.Flush(); err != nil {
		logger.Fatal(err)
	}
	h.lastFlushTime = time.Now()
}
