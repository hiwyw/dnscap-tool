package types

import (
	"encoding/json"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
)

type DnsEvent struct {
	// 常规属性
	EventTime            time.Time `json:"EventTime"`
	SourceIP             string    `json:"SourceIP"`
	SourcePort           uint16    `json:"SourcePort"`
	DestinationIP        string    `json:"DestinationIP"`
	DestinationPort      uint16    `json:"DestinationPort"`
	TranscationID        uint16    `json:"TranscationID"`
	View                 string    `json:"View"`
	Domain               string    `json:"Domain"`
	QueryClass           string    `json:"QueryClass"`
	QueryType            string    `json:"QueryType"`
	Rcode                string    `json:"Rcode"`
	Response             bool      `json:"Response"`
	Authoritative        bool      `json:"Authoritative"`
	Truncated            bool      `json:"Truncated"`
	RecursionDesired     bool      `json:"RecursionDesired"`
	RecursionAvailable   bool      `json:"RecursionAvailable"`
	Zero                 bool      `json:"Zero"`
	AuthenticatedData    bool      `json:"AuthenticatedData"`
	CheckingDisabled     bool      `json:"CheckingDisabled"`
	DelayMicrosecond     int64     `json:"DelayMicrosecond"`
	Answer               []RR      `json:"Answer"`
	Authority            []RR      `json:"Authority"`
	Additional           []RR      `json:"Additional"`
	Edns                 string    `json:"Edns"`
	EdnsClientSubnet     string    `json:"EdnsClientSubnet"`
	EdnsClientSubnetInfo IpInfo    `json:"EdnsClientSubnetInfo"`

	// 扩展IP属性
	SourceIpInfo IpInfo `json:"SourceIpInfo"`
	AnswerIP     string `json:"AnswerIP"`
	AnswerIpInfo IpInfo `json:"AnswerIpInfo"`

	// 隧道安全属性
	SecondLevelDomain     string  `yaml:"SecondLevelDomain"`
	ByteLength            uint32  `json:"ByteLength"`
	QueryByteLength       uint32  `json:"QueryByteLength"`
	SubdomainByteLength   uint32  `json:"SubdomainByteLength"`
	LabelCount            uint32  `json:"LabelCount"`
	SubdomainLabelCount   uint32  `json:"SubdomainLabelCount"`
	SubdomainEntropy      float64 `json:"SubdomainEntropy"`      // 子域名信息熵
	SubdomainLabelEncoded bool    `json:"SubdomainLabelEncoded"` // 子域名是否存在特定编码，如hex|base32|base64

	// 其他扩展属性
	TrafficDirection string `json:"TrafficDirection"` // DNS事件方向，有client_query|client_response|recusion_query|recusion_response
}

type RR struct {
	Domain string `json:"Domain"`
	TTL    uint32 `json:"TTL"`
	Rclass string `json:"Rclass"`
	Rtype  string `json:"Rtype"`
	Rdata  string `json:"Rdata"`
}

type IpInfo struct {
	IP       string `json:"IP"`
	Country  string `json:"Country"`
	Province string `json:"Province"`
	City     string `json:"City"`
	County   string `json:"County"`
	Isp      string `json:"Isp"`
	DC       string `json:"DC"`
	App      string `json:"App"`
	Custom   string `json:"Custom"`
}

func (e *DnsEvent) FromMsg(msg *dns.Msg) {
	e.TranscationID = msg.Id

	if len(msg.Question) > 0 {
		e.Domain = msg.Question[0].Name
		e.QueryClass = dns.ClassToString[msg.Question[0].Qclass]
		e.QueryType = dns.TypeToString[msg.Question[0].Qtype]
	}

	e.Rcode = dns.RcodeToString[msg.Rcode]
	e.Response = msg.Response
	e.Authoritative = msg.Response
	e.Truncated = msg.Truncated
	e.RecursionDesired = msg.RecursionDesired
	e.RecursionAvailable = msg.RecursionAvailable
	e.Zero = msg.Zero
	e.AuthenticatedData = msg.AuthenticatedData
	e.CheckingDisabled = msg.CheckingDisabled

	e.Answer, _, _ = convertMsgRRs(msg.Answer)
	if len(e.Answer) > 0 {
		if e.QueryType == dns.TypeToString[dns.TypeA] || e.QueryType == dns.TypeToString[dns.TypeAAAA] {
			for _, i := range e.Answer {
				if i.Rtype == e.QueryType {
					e.AnswerIP = i.Rdata
				}
			}
		}
	}

	e.Authority, _, _ = convertMsgRRs(msg.Ns)

	add, edns, ecs_ip := convertMsgRRs(msg.Extra)

	e.Additional = add
	e.Edns = edns
	e.EdnsClientSubnet = ecs_ip
	e.ByteLength = uint32(msg.Len())
}

func convertMsgRRs(mrrs []dns.RR) ([]RR, string, string) {
	if len(mrrs) > 0 {
		rrs := []RR{}
		var edns, ecs string
		for _, mrr := range mrrs {
			if opt, ok := mrr.(*dns.OPT); ok {
				optStr := strings.ReplaceAll(opt.String(), "\n", "")
				edns += optStr
				for _, o := range opt.Option {
					if _, ok := o.(*dns.EDNS0_SUBNET); ok {
						ecs = o.String()
					}
				}
			} else {
				rr := new(RR)
				rr.FromMsgRR(mrr)
				rrs = append(rrs, *rr)
			}
		}
		return rrs, edns, ecs
	}
	return []RR{}, "", ""
}

func (rr *RR) FromMsgRR(mrr dns.RR) {
	columns := strings.Split(strings.ReplaceAll(mrr.String(), "\n", ""), "\t")
	if len(columns) < 5 {
		return
	}

	ttl, _ := strconv.Atoi(columns[1])
	rr.TTL = uint32(ttl)

	rr.Domain = columns[0]
	rr.Rclass = columns[2]
	rr.Rtype = columns[3]
	rr.Rdata = strings.Join(columns[4:], " ")
}

func (e *DnsEvent) ExecMiddlewareFunc(fn func(e *DnsEvent)) {
	fn(e)
}

func (e *DnsEvent) JsonString() string {
	b, _ := json.Marshal(e)
	return string(b)
}
