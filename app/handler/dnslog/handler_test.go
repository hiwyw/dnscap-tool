package dnslog

import (
	"bufio"
	"encoding/json"
	"log"
	"testing"
	"time"

	"github.com/hiwyw/dnscap-tool/app/types"
	"github.com/natefinch/lumberjack"
)

func BenchmarkDnslogWrite(b *testing.B) {
	jsonStr := `{"EventTime":"2023-09-07T09:57:20.631236+08:00","SourceIP":"2a01:111:4000:10::2","SourcePort":53,"DestinationIP":"fec0:0:0:21::23","DestinationPort":47628,"TranscationID":54835,"View":"","Domain":"onedscolprdwus01.westus.cloudapp.azure.com.","QueryClass":"IN","QueryType":"A","Rcode":"NOERROR","Response":true,"Authoritative":true,"Truncated":false,"RecursionDesired":false,"RecursionAvailable":false,"Zero":false,"AuthenticatedData":true,"CheckingDisabled":false,"DelayMicrosecond":0,"Answer":[{"Domain":"onedscolprdwus01.westus.cloudapp.azure.com.","TTL":10,"Rclass":"IN","Rtype":"A","Rdata":"20.189.173.2"}],"Authority":[],"Additional":[],"Edns":";; OPT PSEUDOSECTION:; EDNS: version 0; flags:; udp: 1232","EdnsClientSubnet":"","EdnsClientSubnetInfo":{"IP":"","Country":"","Province":"","City":"","County":"","Isp":"","DC":"","App":"","Custom":""},"SourceIpInfo":{"IP":"2a01:111:4000:10::2","Country":"英国","Province":"","City":"","County":"","Isp":"","DC":"","App":"","Custom":""},"AnswerIP":"20.189.173.2","AnswerIpInfo":{"IP":"20.189.173.2","Country":"保留IP","Province":"","City":"","County":"","Isp":"","DC":"","App":"","Custom":""},"SecondLevelDomain":"azure.com.","ByteLength":129,"SubdomainByteLength":34,"LabelCount":6,"SubdomainLabelCount":4,"SubdomainEntropy":3.8431390622295662,"SubdomainLabelEncoded":true,"TrafficDirection":""}`

	e := &types.DnsEvent{}
	if err := json.Unmarshal([]byte(jsonStr), e); err != nil {
		log.Panic(err)
	}

	writer := &lumberjack.Logger{
		Filename:   "dnslog.log",
		MaxSize:    3000,
		MaxBackups: 5,
		MaxAge:     3,
		Compress:   true,
	}

	buf := bufio.NewWriterSize(writer, writerBuffSize)

	ch1 := make(chan string, 10)
	ch2 := make(chan string, 10)
	ch3 := make(chan string, 10)
	ch4 := make(chan string, 10)
	ch5 := make(chan string, 10)
	ch6 := make(chan string, 10)
	ch7 := make(chan string, 10)
	ch8 := make(chan string, 10)

	go func() {
		for {
			in := e.JsonString() + "\n"
			ch1 <- in
		}
	}()

	go func() {
		for {
			in := e.JsonString() + "\n"
			ch2 <- in
		}
	}()

	go func() {
		for {
			in := e.JsonString() + "\n"
			ch3 <- in
		}
	}()

	go func() {
		for {
			in := e.JsonString() + "\n"
			ch4 <- in
		}
	}()

	go func() {
		for {
			in := e.JsonString() + "\n"
			ch5 <- in
		}
	}()

	go func() {
		for {
			in := e.JsonString() + "\n"
			ch6 <- in
		}
	}()

	go func() {
		for {
			in := e.JsonString() + "\n"
			ch7 <- in
		}
	}()

	go func() {
		for {
			in := e.JsonString() + "\n"
			ch8 <- in
		}
	}()

	var flushTime time.Time

	for i := 0; i < b.N; i++ {
		select {
		case s1 := <-ch1:
			_, err := buf.Write([]byte(s1))
			if err != nil {
				log.Panic(err)
			}
			if buf.Available() < 1024*2 {
				if err := buf.Flush(); err != nil {
					log.Panic(err)
				}
				flushTime = time.Now()
			}

			if time.Since(flushTime) > time.Second*1 {
				if err := buf.Flush(); err != nil {
					log.Panic(err)
				}
				flushTime = time.Now()
			}
		case s2 := <-ch2:
			_, err := buf.Write([]byte(s2))
			if err != nil {
				log.Panic(err)
			}
			if buf.Available() < 1024*2 {
				if err := buf.Flush(); err != nil {
					log.Panic(err)
				}
				flushTime = time.Now()
			}

			if time.Since(flushTime) > time.Second*1 {
				if err := buf.Flush(); err != nil {
					log.Panic(err)
				}
				flushTime = time.Now()
			}
		case s3 := <-ch3:
			_, err := buf.Write([]byte(s3))
			if err != nil {
				log.Panic(err)
			}
			if buf.Available() < 1024*2 {
				if err := buf.Flush(); err != nil {
					log.Panic(err)
				}
				flushTime = time.Now()
			}

			if time.Since(flushTime) > time.Second*1 {
				if err := buf.Flush(); err != nil {
					log.Panic(err)
				}
				flushTime = time.Now()
			}
		case s4 := <-ch4:
			_, err := buf.Write([]byte(s4))
			if err != nil {
				log.Panic(err)
			}
			if buf.Available() < 1024*2 {
				if err := buf.Flush(); err != nil {
					log.Panic(err)
				}
				flushTime = time.Now()
			}

			if time.Since(flushTime) > time.Second*1 {
				if err := buf.Flush(); err != nil {
					log.Panic(err)
				}
				flushTime = time.Now()
			}

		case s5 := <-ch5:
			_, err := buf.Write([]byte(s5))
			if err != nil {
				log.Panic(err)
			}
			if buf.Available() < 1024*2 {
				if err := buf.Flush(); err != nil {
					log.Panic(err)
				}
				flushTime = time.Now()
			}

			if time.Since(flushTime) > time.Second*1 {
				if err := buf.Flush(); err != nil {
					log.Panic(err)
				}
				flushTime = time.Now()
			}

		case s6 := <-ch6:
			_, err := buf.Write([]byte(s6))
			if err != nil {
				log.Panic(err)
			}
			if buf.Available() < 1024*2 {
				if err := buf.Flush(); err != nil {
					log.Panic(err)
				}
				flushTime = time.Now()
			}

			if time.Since(flushTime) > time.Second*1 {
				if err := buf.Flush(); err != nil {
					log.Panic(err)
				}
				flushTime = time.Now()
			}

		case s7 := <-ch7:
			_, err := buf.Write([]byte(s7))
			if err != nil {
				log.Panic(err)
			}
			if buf.Available() < 1024*2 {
				if err := buf.Flush(); err != nil {
					log.Panic(err)
				}
				flushTime = time.Now()
			}

			if time.Since(flushTime) > time.Second*1 {
				if err := buf.Flush(); err != nil {
					log.Panic(err)
				}
				flushTime = time.Now()
			}

		case s8 := <-ch8:
			_, err := buf.Write([]byte(s8))
			if err != nil {
				log.Panic(err)
			}
			if buf.Available() < 1024*2 {
				if err := buf.Flush(); err != nil {
					log.Panic(err)
				}
				flushTime = time.Now()
			}

			if time.Since(flushTime) > time.Second*1 {
				if err := buf.Flush(); err != nil {
					log.Panic(err)
				}
				flushTime = time.Now()
			}
		}

	}
	buf.Flush()
}
