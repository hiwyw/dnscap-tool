package ipinfo

import (
	"context"
	"net"
	"os"
	"strings"
	"time"

	"github.com/jszwec/csvutil"

	"github.com/hiwyw/dnscap-tool/app/logger"
	"github.com/hiwyw/dnscap-tool/app/pkg/netradix"
	"github.com/hiwyw/dnscap-tool/app/types"
)

func NewHandler(ctx context.Context, geoipFile string) *Handler {
	h := &Handler{
		ctx:   ctx,
		tree4: netradix.NewNetRadixTree(),
		tree6: netradix.NewNetRadixTree(),
	}

	csvInput, err := os.ReadFile(geoipFile)
	if err != nil {
		logger.Fatal(err)
	}

	var subnets []SubnetInfoCsv
	if err := csvutil.Unmarshal(csvInput, &subnets); err != nil {
		logger.Fatal(err)
	}

	isV6 := func(s string) bool {
		return strings.Contains(s, ":")
	}

	convertSi := func(s SubnetInfoCsv) SubnetInfo {
		return SubnetInfo{s.Country, s.Province, s.City, s.County, s.Isp, s.DC, s.App, s.Custom}
	}

	beginT := time.Now()
	for _, s := range subnets {
		if isV6(s.Subnet) {
			if err := h.tree6.Add(s.Subnet, convertSi(s)); err != nil {
				logger.Fatalf("add subnet failed %s %s", s.Subnet, err)
			} else {
				if err := h.tree4.Add(s.Subnet, convertSi(s)); err != nil {
					logger.Fatalf("add subnet failed %s %s", s.Subnet, err)
				}
			}

		}
	}
	logger.Infof("load addr file succeed, cost %s", time.Since(beginT))

	return h
}

type SubnetInfoCsv struct {
	Subnet   string `json:"subnet" csv:"subnet"`
	Country  string `json:"country" csv:"country"`
	Province string `json:"province" csv:"province"`
	City     string `json:"city" csv:"city"`
	County   string `json:"county" csv:"county"`
	Isp      string `json:"isp" csv:"isp"`
	DC       string `json:"dc" csv:"dc"`
	App      string `json:"app" csv:"app"`
	Custom   string `json:"custom" csv:"custom"`
}

type SubnetInfo struct {
	Country  string `json:"country" csv:"country"`
	Province string `json:"province" csv:"province"`
	City     string `json:"city" csv:"city"`
	County   string `json:"county" csv:"county"`
	Isp      string `json:"isp" csv:"isp"`
	DC       string `json:"dc" csv:"dc"`
	App      string `json:"app" csv:"app"`
	Custom   string `json:"custom" csv:"custom"`
}

type Handler struct {
	ctx   context.Context
	tree4 *netradix.NetRadixTree
	tree6 *netradix.NetRadixTree
}

func (h *Handler) Handle(e *types.DnsEvent) *types.DnsEvent {
	r1, ok := h.search(net.ParseIP(e.SourceIP))
	if ok {
		e.ExecMiddlewareFunc(func(e *types.DnsEvent) {
			e.SourceIpInfo = subnetInfo2Ipinfo(e.SourceIP, &r1)
		})
	}

	if e.AnswerIP != "" {
		r2, ok := h.search(net.ParseIP(e.AnswerIP))
		if ok {
			e.ExecMiddlewareFunc(func(e *types.DnsEvent) {
				e.AnswerIpInfo = subnetInfo2Ipinfo(e.AnswerIP, &r2)
			})
		}
	}

	if e.EdnsClientSubnet == "" {
		return e
	}

	ecs, _, _ := net.ParseCIDR(e.EdnsClientSubnet)
	r3, ok := h.search(ecs)
	if ok {
		e.ExecMiddlewareFunc(func(e *types.DnsEvent) {
			e.EdnsClientSubnetInfo = subnetInfo2Ipinfo(ecs.String(), &r3)
		})
	}
	return e
}

func subnetInfo2Ipinfo(ip string, subnetInfo *SubnetInfo) types.IpInfo {
	if subnetInfo != nil {
		return types.IpInfo{
			IP:       ip,
			Country:  subnetInfo.Country,
			Province: subnetInfo.Province,
			City:     subnetInfo.City,
			County:   subnetInfo.County,
			Isp:      subnetInfo.Isp,
			DC:       subnetInfo.DC,
			App:      subnetInfo.App,
			Custom:   subnetInfo.Custom,
		}
	}
	return types.IpInfo{}
}

func (h *Handler) search(ip net.IP) (SubnetInfo, bool) {
	if ip.To4() != nil {
		r, ok := h.tree4.SearchBest(ip)
		if !ok {
			return SubnetInfo{}, false
		}
		return r.(SubnetInfo), true
	}

	r, ok := h.tree6.SearchBest(ip)
	if !ok {
		return SubnetInfo{}, false
	}
	return r.(SubnetInfo), true
}
