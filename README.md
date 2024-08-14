# Readme
## 说明
DNS抓包日志及分析工具，支持基于离线抓包文件或实时在线抓包解析并计算填充字段及输出日志文件或数据库文件（duckdb）
## 配置
```yaml
input_type: file  # 输入源类型，file--->离线抓包文件，capture--->实时抓包
capture_files:  # 离线抓包文件列表，仅在input_type为file时生效
  - dns.pcap   # 离线抓包文件名
device_name: any  # 实时抓包网卡设备名称
bpf_filter: udp and port 53  # 数据包获取过滤器，语法同tcpdump，建议若无必要，保持使用udp and port 53即可
decode_worker_count: 4 # 用于数据包解析的线程数
handler_worker_count: 2 # 用于数据包解析后处理的线程数
middleware_handlers:  # 程序加载的中间件插件列表，请保持默认
  - delay
  - ipinfo
  - tunnel_sec
  - traffic_direction
result_handlers: # 程序加载的结果插件列表，请保持默认
  - dnslog
  - dnsdb
session: # 会话插件，通过匹配五元组+transcation id的方式建立会话表，并以此计算解析时延及请求包大小，注意使用该插件时，程序不支持多线程并行处理，decode_worker_count和handler_worker_count会被设置为1
  enable: false # 插件功能开关
  session_cache_size: 100000  # 会话表缓存大小，保持默认即可
ipinfo: # ip信息插件
  enable: false
  geoip_filename: addr.csv
tunnel_sec: # 隧道安全插件
  enable: false # 插件功能开关
  special_tlds: # 特殊顶级域列表
    - in-addr.arpa
    - ip6.arpa
  enable_subdomain_entropy: true # 子域名信息熵功能开关
  enable_subdomain_encoding_detect: true # 子域名编码探测功能开关
  encoding_detect_least_label_length: 16 # 子域名编码探测最小标签字节数
traffic_direction: # 流量方向插件
  enable: false
  self_ips: # DNS Server自身IP列表
    - 192.168.134.200
dnslog: # dns日志输出插件
  enable: false # 插件功能开关
  filename: result/dnslog.log # dns日志文件名
  max_file_size: 1000 # 单个dns日志文件大小
  max_file_count: 10 # 最多保留的日志文件数量
  max_file_age: 10 # 最多保留的日志时间，单位天
  format: json # 输出日志格式，有json和csv可选
dnsdb: # dns事件数据库输出插件
  enable: false # 插件功能开关
  filename: result/dnslog.db # duckdb数据库文件名
  max_file_row_count: 100000000 # 单个数据库文件的最大行数
  max_file_count: 10 # 最多保留的数据库文件数
  max_rolling_interval: 24h # 轮滚时间
enable_debug: false # debug日志开关
status_report_interval: 3s # 运行状态报告间隔
pprof_enable: false # 性能调试开关
pprof_http_port: 8000 # 性能调试http监听端口
```
### IP地址库
IP地址库为csv格式，示例如下：
```csv
subnet,country,province,city,county,isp,dc,app,custom
1.0.0.0/24,美国,,,,,,,
1.0.1.0/24,中国,福建,福州,,电信,,,
```
字段说明：
* subnet: 网络地址/掩码
* country: 国家
* province: 省/州
* city: 城市
* county: 区县
* isp: 运营商
* dc: 数据中心
* app: 应用
* custom: 自定义

所有字段格式均为字符串

## 日志格式
示例日志：
```json
{
  "EventTime": "2023-09-07T09:57:20.631236+08:00",
  "SourceIP": "2a01:111:4000:10::2",
  "SourcePort": 53,
  "DestinationIP": "fec0:0:0:21::23",
  "DestinationPort": 47628,
  "TranscationID": 54835,
  "View": "",
  "Domain": "onedscolprdwus01.westus.cloudapp.azure.com.",
  "QueryClass": "IN",
  "QueryType": "A",
  "Rcode": "NOERROR",
  "Response": true,
  "Authoritative": true,
  "Truncated": false,
  "RecursionDesired": false,
  "RecursionAvailable": false,
  "Zero": false,
  "AuthenticatedData": true,
  "CheckingDisabled": false,
  "DelayMicrosecond": 0,
  "Answer": [
    {
      "Domain": "onedscolprdwus01.westus.cloudapp.azure.com.",
      "TTL": 10,
      "Rclass": "IN",
      "Rtype": "A",
      "Rdata": "20.189.173.2"
    }
  ],
  "Authority": [],
  "Additional": [],
  "Edns": ";; OPT PSEUDOSECTION:; EDNS: version 0; flags:; udp: 1232",
  "EdnsClientSubnet": "",
  "EdnsClientSubnetInfo": {
    "IP": "",
    "Country": "",
    "Province": "",
    "City": "",
    "County": "",
    "Isp": "",
    "DC": "",
    "App": "",
    "Custom": ""
  },
  "SourceIpInfo": {
    "IP": "2a01:111:4000:10::2",
    "Country": "英国",
    "Province": "",
    "City": "",
    "County": "",
    "Isp": "",
    "DC": "",
    "App": "",
    "Custom": ""
  },
  "AnswerIP": "20.189.173.2",
  "AnswerIpInfo": {
    "IP": "20.189.173.2",
    "Country": "保留IP",
    "Province": "",
    "City": "",
    "County": "",
    "Isp": "",
    "DC": "",
    "App": "",
    "Custom": ""
  },
  "SecondLevelDomain": "azure.com.",
  "ByteLength": 30,
  "QueryByteLength": 129,
  "SubdomainByteLength": 34,
  "LabelCount": 6,
  "SubdomainLabelCount": 4,
  "SubdomainEntropy": 3.8431390622295662,
  "SubdomainLabelEncoded": true,
  "TrafficDirection": "recursion_response"
}
```

仅解释部分字段含义：
* 域名所属二级域: `"SecondLevelDomain": "azure.com.",`
* 数据包大小: `"ByteLength": 129,`
* 请求数据包大小: `"QueryByteLength": 129,`，仅在响应包事件中存在，用于计算请求响应比判断是否为隧道流量
* 子域名字节数: `"SubdomainByteLength": 34,`
* 域名总标签数: `"LabelCount": 6,`
* 子域名标签数: `"SubdomainLabelCount": 4,`
* 子域名信息熵: `"SubdomainEntropy": 3.8431390622295662,`
* 子域名标签是否被编码: `"SubdomainLabelEncoded": true,`
* 流量方向: `"TrafficDirection": "recursion_response"`，有`client_query` `client_response` `recursion_query` `recursion_response` 4种值

## 使用方式
### 运行程序
```bash
./dnscap-tool -config config.yaml
```

### 查看系统当前网卡信息
主要用于windows环境下使用，windows网卡名称为特定串码，无法直观查看
```bash
./dnscap-tool -devices
```

### 程序运行状态日志说明
日志示例：
```
2024-08-07T09:30:56.484+0800|info|app/app.go:205|running status: {"startup_time":"2024-08-07T09:30:53.484754+08:00","running_time":"3.000006125s","total_event_count":606499,"error_event_count":0,"avg_event_rate":202164,"latest_event_time":"2024-06-19T17:34:47.073946+08:00"}
```
字段说明：
* 启动时间: `"startup_time":"2024-08-07T09:30:53.484754+08:00"`
* 运行时间: `"running_time":"3.000006125s"`
* 处理的dns事件数（dns数据包数）: `"total_event_count":606499`
* 错误事件数（即解析失败的包数）: `"error_event_count":0`
* 平均事件处理速率: `"avg_event_rate":202164`
* 最近事件事件（最近一个dns数据包中的时间）: `"latest_event_time":"2024-06-19T17:34:47.073946+08:00"`
