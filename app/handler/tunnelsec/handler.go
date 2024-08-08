package tunnelsec

import (
	"context"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"math"

	"github.com/miekg/dns"
	"github.com/zdnscloud/g53"

	"github.com/hiwyw/dnscap-tool/app/types"
)

func NewHandler(ctx context.Context, specalTlds []string, enableSubdomainEntropy, enableSubdomainEncodingDetect bool, encodingDetectLeastLabelLength uint) *Handler {
	h := &Handler{
		ctx:                            ctx,
		specalTlds:                     map[string]struct{}{},
		enableSubdomainEntropy:         enableSubdomainEntropy,
		enableSubdomainEncodingDetect:  enableSubdomainEncodingDetect,
		encodingDetectLeastLabelLength: encodingDetectLeastLabelLength,
	}

	for _, i := range specalTlds {
		h.specalTlds[dns.Fqdn(i)] = struct{}{}
	}

	return h
}

type Handler struct {
	ctx                            context.Context
	specalTlds                     map[string]struct{}
	enableSubdomainEntropy         bool
	enableSubdomainEncodingDetect  bool
	encodingDetectLeastLabelLength uint
}

func (h *Handler) Handle(e *types.DnsEvent) *types.DnsEvent {
	name, err := g53.NameFromString(e.Domain)
	if err != nil {
		return e
	}

	lc := name.LabelCount()
	if lc <= 3 {
		return e
	}

	parent, _ := name.Parent(lc - 3)
	if _, ok := h.specalTlds[parent.String(false)]; ok {
		if lc > 4 {
			parent, _ = name.Parent(lc - 4)
		}
	}
	sld := parent.String(false)
	subname, _ := name.Subtract(parent)
	subdomainLength := uint32(subname.Length())
	subdomainLableCount := uint32(subname.LabelCount())

	var subdomainEntropy float64
	if h.enableSubdomainEntropy {
		subdomainEntropy = calcEntropy(subname.String(true))
	}

	var subdomainLabelEncoded bool
	if h.enableSubdomainEncodingDetect {
		subdomainLabelEncoded = existEncoding(subname, h.encodingDetectLeastLabelLength)
	}

	e.ExecMiddlewareFunc(func(e *types.DnsEvent) {
		e.SecondLevelDomain = sld
		e.SubdomainByteLength = subdomainLength
		e.SubdomainLabelCount = subdomainLableCount
		e.LabelCount = uint32(name.LabelCount())
		e.SubdomainEntropy = subdomainEntropy
		e.SubdomainLabelEncoded = subdomainLabelEncoded
	})
	return e
}

func calcEntropy(s string) float64 {
	fm := make(map[rune]int)
	for _, c := range s {
		if _, ok := fm[c]; ok {
			fm[c]++
		} else {
			fm[c] = 1
		}
	}

	entropy := 0.0
	totalChars := len(s)
	for _, f := range fm {
		p := float64(f) / float64(totalChars)
		entropy -= p * math.Log2(p)
	}
	return entropy
}

func existEncoding(subname *g53.Name, leastLabelLength uint) bool {
	var fs []func(s string) bool = []func(s string) bool{
		isHex,
		isBase32,
		isBase64,
	}

	for i := 0; i < int(subname.LabelCount()); i++ {
		n, _ := subname.Split(uint(i), 1)
		if n.Length() < leastLabelLength {
			continue
		}
		for _, f := range fs {
			if f(n.String(true)) {
				return true
			}
		}
	}
	return false
}

func isHex(s string) bool {
	_, err := hex.DecodeString(s)
	return err == nil
}

func isBase32(s string) bool {
	_, err := base32.StdEncoding.DecodeString(s)
	return err == nil
}

func isBase64(s string) bool {
	_, err := base64.StdEncoding.DecodeString(s)
	return err == nil
}
