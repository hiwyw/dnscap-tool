package dnslog

import (
	"bufio"
	"context"
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
	lastFlushTime time.Time
}

func NewHandler(ctx context.Context, filename string, maxsize, fileCount, fileAge int, finalizer func()) *LogHandler {
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
		ch: make(chan string, recviceBufferLength),
	}
	h.buffer = bufio.NewWriterSize(h.writer, writerBuffSize)

	go h.loop()
	return h
}

func (h *LogHandler) loop() {
	for {
		select {
		case s, ok := <-h.ch:
			if !ok {
				h.flush()
				logger.Infof("dnslog handler exiting")
				return
			}
			h.write(s)
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

func (h *LogHandler) Handle(e *types.DnsEvent) {
	h.ch <- e.JsonString() + "\n"
}

func (h *LogHandler) write(s string) {
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
