package dnsdb

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/hiwyw/dnscap-tool/app/types"
)

func BenchmarkRollingDBWrite(b *testing.B) {
	w := &DbRollingWriter{
		filename:     "",
		maxRowCount:  100000000,
		maxInterval:  time.Hour,
		maxFileCount: 5,
	}

	w.initNew()

	eventJsonStr := `{"query_time":"2023-09-07T09:57:20.631236+08:00","source_ip":"2a01:111:4000:10::2","source_port":53,"destination_ip":"fec0:0:0:21::23","destination_port":47628,"transcation_id":54835,"view":"","domain":"onedscolprdwus01.westus.cloudapp.azure.com.","query_class":"IN","query_type":"A","rcode":"NOERROR","response":true,"authoritative":true,"truncated":false,"recursion_desired":false,"recursion_available":false,"zero":false,"authenticated_data":true,"checking_disabled":false,"delay_microsecond":0,"answer_data":[{"domain":"onedscolprdwus01.westus.cloudapp.azure.com.","ttl":10,"rclass":"IN","rtype":"A","rdata":"20.189.173.2"}],"authority_data":[],"additional_data":[],"edns_data":";; OPT PSEUDOSECTION:; EDNS: version 0; flags:; udp: 1232","edns_client_subnet":"","edns_client_subnet_info":{"ip":"","country":"","province":"","city":"","county":"","isp":"","dc":"","app":"","custom":""},"source_ip_info":{"ip":"","country":"","province":"","city":"","county":"","isp":"","dc":"","app":"","custom":""},"answer_ip":"20.189.173.2","answer_ips_info":{"ip":"","country":"","province":"","city":"","county":"","isp":"","dc":"","app":"","custom":""},"SecondLevelDomain":"azure.com.","byte_length":129,"subdomain_byte_length":34,"lable_count":6,"subdomain_lable_count":4,"subdomain_entropy":0,"subdomain_label_encoded":false,"traffic_direction":"recursion_response"}`

	event := &types.DnsEvent{}
	if err := json.Unmarshal([]byte(eventJsonStr), event); err != nil {
		panic(err)
	}

	for i := 0; i < b.N; i++ {
		w.Write(event)
	}
	w.appender.Flush()
}
