package session

import (
	"context"
	"time"

	lru "github.com/hashicorp/golang-lru"

	"github.com/hiwyw/dnscap-tool/app/logger"
	"github.com/hiwyw/dnscap-tool/app/types"
)

func NewHandler(ctx context.Context, sessionCaheSize int) *Handler {
	h := &Handler{
		ctx:            ctx,
		sessionManager: NewSessionCache(sessionCaheSize),
	}

	return h
}

type Handler struct {
	ctx            context.Context
	sessionManager *SessionCache
}

func (h *Handler) Handle(e *types.DnsEvent) *types.DnsEvent {
	switch e.Response {
	case false:
		k := SessionKey{
			SrcIP:     e.SourceIP,
			DstIP:     e.DestinationIP,
			SrcPort:   e.SourcePort,
			DstPort:   e.DestinationPort,
			TransID:   e.TranscationID,
			Domain:    e.Domain,
			QueryType: e.QueryType,
		}

		if ok := h.sessionManager.Add(k, SessionValue{
			QueryTime:  e.EventTime,
			ByteLength: e.ByteLength,
		}); ok {
			logger.Debugf("session cache full %d", h.sessionManager.c.Len())
		}
		return e
	case true:
		k := SessionKey{
			SrcIP:     e.DestinationIP,
			DstIP:     e.SourceIP,
			SrcPort:   e.DestinationPort,
			DstPort:   e.SourcePort,
			TransID:   e.TranscationID,
			Domain:    e.Domain,
			QueryType: e.QueryType,
		}

		v, ok := h.sessionManager.Get(k)
		if !ok {
			logger.Debugf("session fetch failed due to not found: %v", k)
			return e
		}

		e.ExecMiddlewareFunc(func(e *types.DnsEvent) {
			e.DelayMicrosecond = e.EventTime.Sub(v.QueryTime).Microseconds()
			e.QueryByteLength = v.ByteLength
		})

		h.sessionManager.Delete(k)
		return e
	}
	return e
}

func NewSessionCache(size int) *SessionCache {
	lruc, _ := lru.New(size)

	return &SessionCache{
		c: lruc,
	}
}

type SessionCache struct {
	c *lru.Cache
}

func (s *SessionCache) Add(k SessionKey, v SessionValue) (evicted bool) {
	evicted = s.c.Add(k, v)
	return
}

func (s *SessionCache) Delete(k SessionKey) {
	s.c.Remove(k)
}

func (s *SessionCache) Get(k SessionKey) (SessionValue, bool) {
	v, ok := s.c.Peek(k)
	if !ok {
		return SessionValue{}, false
	}
	return v.(SessionValue), true
}

type SessionKey struct {
	SrcIP     string
	DstIP     string
	SrcPort   uint16
	DstPort   uint16
	TransID   uint16
	Domain    string
	QueryType string
}

type SessionValue struct {
	QueryTime  time.Time
	ByteLength uint32
}
