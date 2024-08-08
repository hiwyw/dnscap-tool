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
	batchWriteTimeout = time.Second * 1

	recviceBufferLength = 10
	writerBuffSize      = 1024 * 8
)

type LogHandler struct {
	ctx       context.Context
	finalizer func()
	writer    *lumberjack.Logger
	buffer    *bufio.Writer
	ch        chan *types.DnsEvent
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
		ch: make(chan *types.DnsEvent, recviceBufferLength),
	}
	h.buffer = bufio.NewWriterSize(h.writer, writerBuffSize)

	go h.loop()
	return h
}

func (h *LogHandler) loop() {
	for {
		select {
		case l, ok := <-h.ch:
			if !ok {
				h.buffer.Flush()
				logger.Infof("dnslog handler exiting")
				return
			}
			h.handle(l)
		case <-time.After(batchWriteTimeout):
			h.buffer.Flush()
		case <-h.ctx.Done():
			h.buffer.Flush()
			logger.Infof("dnslog handler exiting by recvice signal")
			h.finalizer()
			logger.Infof("dnslog handler finalizer succeed")
			return
		}
	}
}

func (h *LogHandler) Handle(e *types.DnsEvent) {
	h.ch <- e
}

func (h *LogHandler) handle(e *types.DnsEvent) {
	if _, err := h.buffer.WriteString(e.JsonString() + "\n"); err != nil {
		logger.Fatal(err)
	}

	if h.buffer.Available() < 1024*2 {
		if err := h.buffer.Flush(); err != nil {
			logger.Fatal(err)
		}
	}
}
