package dnsdb

import (
	"context"
	"database/sql/driver"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/marcboeker/go-duckdb"

	"github.com/hiwyw/dnscap-tool/app/logger"
	"github.com/hiwyw/dnscap-tool/app/types"
)

const (
	tableName = "dnsevent"

	recviceBufferLength = 10
)

func NewHandler(ctx context.Context, filename string, maxRowCount int, maxInterval time.Duration, maxFileCount int, finalizer func()) *Handler {
	h := &Handler{
		ch:        make(chan *types.DnsEvent, recviceBufferLength),
		ctx:       ctx,
		finalizer: finalizer,
		writer:    NewDbRollingWriter(filename, maxRowCount, maxInterval, maxFileCount),
	}
	go h.loop()
	return h
}

type Handler struct {
	ch        chan *types.DnsEvent
	finalizer func()
	ctx       context.Context
	writer    *DbRollingWriter
}

func (h *Handler) loop() {
	for {
		select {
		case e, ok := <-h.ch:
			if !ok {
				h.writer.closeCurrent()
				logger.Infof("dnsdb handler exiting by event channel closed")
				return
			}
			h.writer.Write(e)
		case <-h.ctx.Done():
			logger.Infof("dnsdb handler exiting by recvice signal")
			h.writer.closeCurrent()
			logger.Infof("dnsdb handler exited")
			h.finalizer()
			logger.Infof("dnsdb finalizer succeed")
			return
		}
	}
}

func (h *Handler) Handle(e *types.DnsEvent) {
	h.ch <- e
}

func NewDbRollingWriter(filename string, maxRowCount int, maxInterval time.Duration, maxFileCount int) *DbRollingWriter {
	w := &DbRollingWriter{
		filename:     filename,
		maxRowCount:  maxRowCount,
		maxInterval:  maxInterval,
		maxFileCount: maxFileCount,
	}

	w.initNew()
	return w
}

type DbRollingWriter struct {
	filename      string
	maxRowCount   int
	maxInterval   time.Duration
	maxFileCount  int
	wroteRowCount int
	beginAt       time.Time
	lastUpdateAt  time.Time
	connector     *duckdb.Connector
	connection    driver.Conn
	appender      *duckdb.Appender
}

func (w *DbRollingWriter) Write(e *types.DnsEvent) {
	if w.wroteRowCount >= w.maxRowCount || w.lastUpdateAt.Sub(w.beginAt) >= w.maxInterval {
		logger.Debugf("should roll db, wroteRowLines: %d, maxRowLines: %d, duration since begin: %s, maxInterval: %s", w.wroteRowCount, w.maxRowCount, w.lastUpdateAt.Sub(w.beginAt), w.maxInterval)
		if err := w.Roll(); err != nil {
			logger.Fatal(err)
		}
	}

	if (w.beginAt == time.Time{}) {
		w.beginAt = e.EventTime
	}

	if err := w.writeEvent(e); err != nil {
		logger.Fatal(err)
	}

	w.wroteRowCount += 1
	w.lastUpdateAt = e.EventTime
}

func (w *DbRollingWriter) writeEvent(e *types.DnsEvent) error {
	return w.appender.AppendRow(e.EventTime,
		e.SourceIP,
		e.SourcePort,
		e.DestinationIP,
		e.DestinationPort,
		e.TranscationID,
		e.View,
		e.Domain,
		e.QueryClass,
		e.QueryType,
		e.Rcode,
		e.Response,
		e.Authoritative,
		e.Truncated,
		e.RecursionDesired,
		e.RecursionAvailable,
		e.Zero,
		e.AuthenticatedData,
		e.CheckingDisabled,
		e.DelayMicrosecond,
		e.Answer,
		e.Authority,
		e.Additional,
		e.Edns,
		e.EdnsClientSubnet,
		e.EdnsClientSubnetInfo,
		e.SourceIpInfo,
		e.AnswerIP,
		e.AnswerIpInfo,
		e.SecondLevelDomain,
		e.ByteLength,
		e.SubdomainByteLength,
		e.LabelCount,
		e.SubdomainLabelCount,
		e.SubdomainEntropy,
		e.SubdomainLabelEncoded,
		e.TrafficDirection)
}

func (w *DbRollingWriter) Roll() error {
	if err := w.closeCurrent(); err != nil {
		return err
	}

	newFilename := fmt.Sprintf("%s-%s", w.filename, w.lastUpdateAt.Local().Format(time.RFC3339))
	if err := os.Rename(w.filename, newFilename); err != nil {
		return err
	}

	go w.checkCountAndRemoveIfNeed()

	w.initNew()
	return nil
}

func (w *DbRollingWriter) closeCurrent() error {
	var err error
	if err := w.appender.Flush(); err != nil {
		return err
	}

	err = w.appender.Close()
	if err != nil {
		return err
	}

	err = w.connection.Close()
	if err != nil {
		return err
	}

	err = w.connector.Close()
	return err
}

func (w *DbRollingWriter) checkCountAndRemoveIfNeed() {
	files, err := filepath.Glob(w.filename + "-*")
	if err != nil {
		logger.Errorf("list file failed when check file count %s", err)
	}
	logger.Debugf("rolling check total %d files: %s", len(files), files)

	if len(files) < (w.maxFileCount - 1) {
		return
	}

	var tempT time.Time
	var toDelete string

	for _, f := range files {
		tStr := strings.TrimPrefix(f, w.filename+"-")

		t, err := time.Parse(time.RFC3339, tStr)
		if err != nil {
			logger.Infof("error filename %s will ignore", f)
			continue
		}

		if (tempT == time.Time{}) {
			tempT = t
			toDelete = f
			continue
		}

		if t.Before(tempT) {
			tempT = t
			toDelete = f
		}
	}

	if err := os.Remove(toDelete); err != nil {
		logger.Errorf("remove file %s failed %s", toDelete, err)
		return
	}
	logger.Infof("remove file %s succeed due to reached max file count %d", toDelete, w.maxFileCount)
}

func (w *DbRollingWriter) initNew() {
	var sql string = `CREATE TABLE IF NOT EXISTS dnsevent (
    EventTime DATETIME,
    SourceIP VARCHAR,
    SourcePort USMALLINT,
    DestinationIP VARCHAR,
    DestinationPort USMALLINT,
    TranscationID USMALLINT,
	View VARCHAR,
    Domain VARCHAR,
    QueryClass VARCHAR,
    QueryType VARCHAR,
    Rcode VARCHAR,
    Response BOOLEAN,
    Authoritative BOOLEAN,
    Truncated BOOLEAN,
    RecursionDesired BOOLEAN,
    RecursionAvailable BOOLEAN,
    Zero BOOLEAN,
    AuthenticatedData BOOLEAN,
    CheckingDisabled BOOLEAN,
    DelayMicrosecond BIGINT,
    Answer STRUCT(
        Domain VARCHAR, 
        TTL UINTEGER,
        Rclass VARCHAR,
        Rtype VARCHAR,
        Rdata VARCHAR
        )[],
    Authority STRUCT(
        Domain VARCHAR, 
        TTL UINTEGER,
        Rclass VARCHAR,
        Rtype VARCHAR,
        Rdata VARCHAR
        )[],
    Additional STRUCT(
        Domain VARCHAR, 
        TTL UINTEGER,
        Rclass VARCHAR,
        Rtype VARCHAR,
        Rdata VARCHAR
        )[],
    Edns VARCHAR,
    EdnsClientSubnet VARCHAR,
    EdnsClientSubnetInfo STRUCT(
        IP VARCHAR,
        Country VARCHAR,
        Province VARCHAR,
        City VARCHAR,
		County VARCHAR,
        Isp VARCHAR,
        DC VARCHAR,
        App VARCHAR,
        Custom VARCHAR
    ),
    SourceIpInfo STRUCT(
        IP VARCHAR,
        Country VARCHAR,
        Province VARCHAR,
        City VARCHAR,
		County VARCHAR,
        Isp VARCHAR,
        DC VARCHAR,
        App VARCHAR,
        Custom VARCHAR
    ),
	AnswerIP VARCHAR,
    AnswerIpInfo STRUCT(
        IP VARCHAR,
        Country VARCHAR,
        Province VARCHAR,
        City VARCHAR,
		County VARCHAR,
        Isp VARCHAR,
        DC VARCHAR,
        App VARCHAR,
        Custom VARCHAR
    ),
	SecondLevelDomain VARCHAR,
	ByteLength UINTEGER,
	SubdomainByteLength UINTEGER,
	LabelCount UINTEGER,
	SubdomainLabelCount UINTEGER,
	SubdomainEntropy DOUBLE,
	SubdomainLabelEncoded BOOLEAN,
	TrafficDirection VARCHAR
)`
	connector, err := duckdb.NewConnector(w.filename, func(execer driver.ExecerContext) error {
		_, err := execer.ExecContext(context.Background(), sql, []driver.NamedValue{})
		return err
	})
	if err != nil {
		logger.Fatal(err)
	}
	w.connector = connector

	conn, err := connector.Connect(context.Background())
	if err != nil {
		logger.Fatal(err)
	}
	w.connection = conn

	appender, err := duckdb.NewAppenderFromConn(conn, "", tableName)
	if err != nil {
		logger.Fatal(err)
	}
	w.appender = appender
	w.beginAt = time.Time{}
	w.lastUpdateAt = time.Time{}
	w.wroteRowCount = 0
}
