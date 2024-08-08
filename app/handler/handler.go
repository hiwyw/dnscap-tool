package handler

import (
	"github.com/hiwyw/dnscap-tool/app/types"
)

type MiddlewareHandler interface {
	Handle(e *types.DnsEvent) *types.DnsEvent
}

type ResultHandler interface {
	Handle(e *types.DnsEvent)
}
