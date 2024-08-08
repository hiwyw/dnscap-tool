package trafficdirection

import (
	"context"

	"github.com/hiwyw/dnscap-tool/app/types"
)

func NewHandler(ctx context.Context, selfIps []string) *Handler {
	h := &Handler{
		ctx:     ctx,
		selfIps: map[string]struct{}{},
	}

	for _, i := range selfIps {
		h.selfIps[i] = struct{}{}
	}

	return h
}

type Handler struct {
	ctx     context.Context
	selfIps map[string]struct{}
}

func (h *Handler) Handle(e *types.DnsEvent) *types.DnsEvent {
	var direction string
	_, ok := h.selfIps[e.SourceIP]
	if ok {
		if e.DestinationPort == 53 {
			direction = RecursionQueryDirection
		}
		if e.SourcePort == 53 {
			direction = ClientResponseDirection
		}
	}

	if !ok {
		if e.DestinationPort == 53 {
			direction = ClientQueryDirection
		}
		if e.SourcePort == 53 {
			direction = RecursionResponseDirection
		}
	}

	e.ExecMiddlewareFunc(func(e *types.DnsEvent) {
		e.TrafficDirection = direction
	})
	return e
}

const (
	ClientQueryDirection       = "client_query"
	ClientResponseDirection    = "client_response"
	RecursionQueryDirection    = "recursion_query"
	RecursionResponseDirection = "recursion_response"
)
