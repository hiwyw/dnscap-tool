package config

import (
	"log"
	"os"

	"gopkg.in/yaml.v2"
)

func Load(fp string) *Config {
	c := &Config{}

	fileContent, err := os.ReadFile(fp)
	if err != nil {
		log.Fatalf("read config file %s failed %s", fp, err)
	}

	if err := yaml.Unmarshal(fileContent, c); err != nil {
		log.Fatalf("unmarshal config failed %s", err)
	}

	return c
}

func Generate(fp string) {
	c := &Config{
		InputType: InputTypePcapFile,
		PcapFiles: []string{
			"data.pcap",
		},
		Device:             "any",
		BpfFilter:          "udp and port 53",
		DecodeWorkerCount:  1,
		HandlerWorkerCount: 1,
		MiddlewareHandlers: []MiddlewareHandlerType{
			SessionType,
			IpInfoType,
			TunnelSecType,
			TrafficDirectionType,
		},
		ResultHandlers: []ResultHandlerType{
			DnsLogWriterType,
			DbWriterType,
		},
		SessionConfig: SessionConfig{
			Enable:           true,
			SessionCacheSize: 100000,
		},
		IpInfoConfig: IpInfoConfig{
			Enable:        true,
			GeoIPFilename: "addr.csv",
		},
		TunnelSecConfig: TunnelSecConfig{
			Enable:                         true,
			SpecialTlds:                    SpecialTlds,
			EnableSubdomainEntropy:         true,
			EnableSubdomainEncodingDetect:  true,
			EncodingDetectLeastLabelLength: 16,
		},
		TrafficDirectionConfig: TrafficDirectionConfig{
			Enable: true,
			SelfIps: []string{
				"172.31.21.23",
			},
		},
		DnslogConfig: DnslogConfig{
			Enable:       true,
			Filename:     "result/dnslog.log",
			MaxFileSize:  100,
			MaxFileCount: 10,
			MaxFileAge:   10,
			Format:       JsonLogFormat,
		},
		DnsdbConfig: DnsdbConfig{
			Enable:             true,
			Filename:           "result/dnslog.db",
			MaxFileRowCount:    100000000,
			MaxFileCount:       10,
			MaxRollingInterval: "24h",
		},
		EnableDebug:          false,
		StatusReportInterval: "10s",
		PprofEnable:          false,
		PprofHttpPort:        8000,
	}

	content, err := yaml.Marshal(c)
	if err != nil {
		log.Fatalf("config yaml marshal failed %s", err)
	}

	if err := os.WriteFile(fp, content, 0644); err != nil {
		log.Fatalf("config yaml marshal failed %s", err)
	}
	log.Printf("config file %s generated", fp)
}

type InputType string

const (
	InputTypePcapFile InputType = "file"
	InputTypePcap     InputType = "capture"
)

type Config struct {
	InputType              InputType               `yaml:"input_type"`
	PcapFiles              []string                `yaml:"capture_files"`
	Device                 string                  `yaml:"device_name"`
	BpfFilter              string                  `yaml:"bpf_filter"`
	DecodeWorkerCount      int                     `yaml:"decode_worker_count"`
	HandlerWorkerCount     int                     `yaml:"handler_worker_count"`
	MiddlewareHandlers     []MiddlewareHandlerType `yaml:"middleware_handlers"`
	ResultHandlers         []ResultHandlerType     `yaml:"result_handlers"`
	SessionConfig          SessionConfig           `yaml:"session"`
	IpInfoConfig           IpInfoConfig            `yaml:"ipinfo"`
	TunnelSecConfig        TunnelSecConfig         `yaml:"tunnel_sec"`
	TrafficDirectionConfig TrafficDirectionConfig  `yaml:"traffic_direction"`
	DnslogConfig           DnslogConfig            `yaml:"dnslog"`
	DnsdbConfig            DnsdbConfig             `yaml:"dnsdb"`
	EnableDebug            bool                    `yaml:"enable_debug"`
	StatusReportInterval   string                  `yaml:"status_report_interval"`
	PprofEnable            bool                    `yaml:"pprof_enable"`
	PprofHttpPort          int                     `yaml:"pprof_http_port"`
}

type MiddlewareHandlerType string

const (
	SessionType          MiddlewareHandlerType = "session"
	IpInfoType           MiddlewareHandlerType = "ipinfo"
	TunnelSecType        MiddlewareHandlerType = "tunnel_sec"
	TrafficDirectionType MiddlewareHandlerType = "traffic_direction"
)

type ResultHandlerType string

const (
	DnsLogWriterType ResultHandlerType = "dnslog"
	DbWriterType     ResultHandlerType = "dnsdb"
)

type SessionConfig struct {
	Enable           bool `yaml:"enable"`
	SessionCacheSize int  `yaml:"session_cache_size"`
}

type TunnelSecConfig struct {
	Enable                         bool     `yaml:"enable"`
	SpecialTlds                    []string `yaml:"special_tlds"`
	EnableSubdomainEntropy         bool     `yaml:"enable_subdomain_entropy"`
	EnableSubdomainEncodingDetect  bool     `yaml:"enable_subdomain_encoding_detect"`
	EncodingDetectLeastLabelLength uint     `yaml:"encoding_detect_least_label_length"`
}

type TrafficDirectionConfig struct {
	Enable  bool     `yaml:"enable"`
	SelfIps []string `yaml:"self_ips"`
}

type IpInfoConfig struct {
	Enable        bool   `yaml:"enable"`
	GeoIPFilename string `yaml:"geoip_filename"`
}

type DnslogConfig struct {
	Enable       bool      `yaml:"enable"`
	Filename     string    `yaml:"filename"`
	MaxFileSize  int       `yaml:"max_file_size"`
	MaxFileCount int       `yaml:"max_file_count"`
	MaxFileAge   int       `yaml:"max_file_age"`
	Format       LogFormat `yaml:"format"`
}

type LogFormat string

const (
	JsonLogFormat LogFormat = "json"
	CsvLogFormat  LogFormat = "csv"
)

type DnsdbConfig struct {
	Enable             bool   `yaml:"enable"`
	Filename           string `yaml:"filename"`
	MaxFileRowCount    int    `yaml:"max_file_row_count"`
	MaxFileCount       int    `yaml:"max_file_count"`
	MaxRollingInterval string `yaml:"max_rolling_interval"`
}

var SpecialTlds []string = []string{
	"in-addr.arpa",
	"ip6.arpa",
	"edu.cn",
	"gov.cn",
	"com.cn",
	"net.cn",
	"org.cn",
	"ac.cn",
	"edu.hk",
	"edu.mo",
	"edu.tw",
	"edu.mn",
	"edu.kp",
	"ac.kr",
	"ac.jp",
	"edu.ph",
	"edu.vn",
	"edu.la",
	"edu.kh",
	"edu.mm",
	"ac.th",
	"edu.my",
	"edu.bn",
	"edu.sg",
	"ac.id",
	"edu.tl",
	"edu.np",
	"edu.bt",
	"edu.bd",
	"ac.bd",
	"edu.in",
	"ac.in",
	"edu.pk",
	"ac.lk",
	"edu.mv",
	"edu.kz",
	"edu.kg",
	"edu.uz",
	"edu.tm",
	"edu.af",
	"edu.iq",
	"ac.ir",
	"edu.sy",
	"edu.jo",
	"edu.lb",
	"ac.il",
	"edu.ps",
	"edu.sa",
	"edu.bh",
	"edu.qa",
	"ac.ae",
	"edu.om",
	"edu.ye",
	"edu.ge",
	"edu.az",
	"edu.tr",
	"ac.cy",
	"edu.ee",
	"edu.lv",
	"edu.by",
	"edu.ru",
	"ac.ru",
	"edu.ua",
	"edu.md",
	"edu.pl",
	"edu.sk",
	"ac.at",
	"ac.uk",
	"edu.ie",
	"ac.be",
	"edu.ro",
	"ac.rs",
	"edu.mk",
	"edu.al",
	"edu.gr",
	"edu.me",
	"ac.me",
	"edu.mt",
	"edu.ba",
	"edu.it",
	"edu.es",
	"edu.pt",
	"edu.gi",
	"edu.mx",
	"edu.gl",
	"edu.gt",
	"edu.bz",
	"edu.sv",
	"edu.hn",
	"edu.ni",
	"ac.cr",
	"ac.pa",
	"edu.bs",
	"edu.cu",
	"edu.jm",
	"edu.ht",
	"edu.ag",
	"edu.dm",
	"edu.lc",
	"edu.jm",
	"edu.bb",
	"edu.tt",
	"edu.vg",
	"ac.tc",
	"edu.ky",
	"edu.co",
	"edu.ve",
	"edu.gy",
	"edu.ec",
	"edu.pe",
	"edu.bo",
	"edu.br",
	"edu.ar",
	"edu.uy",
	"edu.au",
	"ac.nz",
	"edu.ki",
	"ac.pg",
	"edu.sb",
	"edu.vu",
	"ac.fj",
	"edu.ws",
	"edu.to",
	"edu.ck",
	"edu.nu",
	"edu.eg",
	"edu.ly",
	"edu.dz",
	"ac.ma",
	"edu.es",
	"edu.sd",
	"edu.et",
	"edu.so",
	"edu.dj",
	"ac.ke",
	"ac.tz",
	"ac.ug",
	"ac.rw",
	"edu.bi",
	"ac.sc",
	"edu.cd",
	"edu.sn",
	"edu.gm",
	"edu.ml",
	"ac.pg",
	"edu.cv",
	"edu.sl",
	"edu.lr",
	"edu.ci",
	"edu.gh",
	"edu.ng",
	"edu.zm",
	"ac.zm",
	"ac.zw",
	"ac.mw",
	"ac.mz",
	"ac.bw",
	"edu.na",
	"ac.za",
	"ac.ls",
	"edu.mg",
	"ac.mu",
}
