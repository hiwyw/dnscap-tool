package types

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/miekg/dns"
	"github.com/panjf2000/ants/v2"

	"github.com/hiwyw/dnscap-tool/app/logger"
)

const chBufferLength = 10

type EventSource interface {
	Events() <-chan *DnsEvent
	ErrEvents() <-chan struct{}
	SetWorkerCount(n int)
}

func NewCaptureSource(ctx context.Context, workerCount int, device, bpf string, finalizer func()) *PcapEventSource {
	return NewPacketEventSource(ctx, workerCount, PcapModeCapture, []string{}, device, bpf, finalizer)
}

func NewFilesSource(ctx context.Context, workerCount int, files []string, bpf string, finalizer func()) *PcapEventSource {
	return NewPacketEventSource(ctx, workerCount, PcapModeFile, files, "", bpf, finalizer)
}

func NewPacketEventSource(ctx context.Context, workerCount int, mode PcapMode, files []string, device, bpf string, finalizer func()) *PcapEventSource {
	s := &PcapEventSource{
		ctx:        ctx,
		mode:       mode,
		files:      files,
		device:     device,
		bpfFilter:  bpf,
		eventCh:    make(chan *DnsEvent, chBufferLength),
		errEventCh: make(chan struct{}, chBufferLength),
		finalizer:  finalizer,
		closeOnce:  sync.Once{},
	}

	pool, err := ants.NewPool(workerCount)
	if err != nil {
		logger.Fatal(err)
	}
	s.pool = pool

	go s.run()
	return s
}

type PcapEventSource struct {
	ctx        context.Context
	mode       PcapMode
	files      []string
	device     string
	bpfFilter  string
	eventCh    chan *DnsEvent
	errEventCh chan struct{}
	pool       *ants.Pool
	finalizer  func()
	closeOnce  sync.Once
}

type PcapMode string

const (
	PcapModeFile    PcapMode = "file"
	PcapModeCapture PcapMode = "capture"
)

func (s *PcapEventSource) Events() <-chan *DnsEvent {
	return s.eventCh
}

func (s *PcapEventSource) SetWorkerCount(n int) {
	s.pool.Tune(n)
}

func (s *PcapEventSource) ErrEvents() <-chan struct{} {
	return s.errEventCh
}

func (s *PcapEventSource) run() {
	switch s.mode {
	case PcapModeCapture:
		s.handleCapture()
	case PcapModeFile:
		s.handleFiles()
	default:
		logger.Fatalf("unknown pcap mode %s", s.mode)
	}
}

func (s *PcapEventSource) handleCapture() {
	handle, err := pcap.OpenLive(s.device, 1500, true, pcap.BlockForever)
	if err != nil {
		logger.Fatalf("open pcap device %s failed %s", s.device, err)
		return
	}
	defer handle.Close()

	if err := handle.SetBPFFilter(s.bpfFilter); err != nil {
		logger.Fatalf("set bfp filter failed [%s] %s", s.bpfFilter, err)
		return
	}
	logger.Infof("set bpf filter succeed [%s]", s.bpfFilter)

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	s.handlePackets(packetSource)
}

func (s *PcapEventSource) handleFiles() {
	logger.Infof("total %d pcap files need to handle", len(s.files))
	for _, f := range s.files {
		logger.Infof("begin handle pcap file %s", f)
		if err := s.handleFile(f); err != nil {
			logger.Errorf("handle pcap file %s failed %s", f, err)
		}
		logger.Infof("end handle pcap file %s", f)
	}
	logger.Infof("all %d pcap files handled done", len(s.files))
	s.close()
}

func (s *PcapEventSource) handleFile(filename string) error {
	handle, err := pcap.OpenOffline(filename)
	if err != nil {
		return fmt.Errorf("open pacp file %s failed %s", filename, err)
	}
	defer handle.Close()

	if err := handle.SetBPFFilter(s.bpfFilter); err != nil {
		return fmt.Errorf("set bpf filter failed [%s] %s", s.bpfFilter, err)
	}
	logger.Infof("set bpf filter succeed [%s]", s.bpfFilter)

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	s.handlePackets(packetSource)
	return nil
}

func (s *PcapEventSource) handlePackets(ps *gopacket.PacketSource) {
	for {
		select {
		case p, ok := <-ps.Packets():
			if !ok {
				if s.mode == PcapModeCapture {
					logger.Infof("handle packets groutinue exiting by no packets")
					s.close()
				}
				if s.mode == PcapModeFile {
					logger.Infof("handle packets groutinue exiting by file EOF")
				}
				return
			}
			s.pool.Submit(func() {
				if p == nil {
					return
				}

				e, err := unpack(p)
				if err != nil {
					logger.Debugf("unpack packet failed %s", err)
					s.errEventCh <- struct{}{}
					return
				}
				s.eventCh <- e
			})
		case <-s.ctx.Done():
			logger.Infof("handle packets groutinue exiting by receive signal")
			s.close()
			return
		}
	}
}

func (s *PcapEventSource) close() {
	s.closeOnce.Do(func() {
		if err := s.pool.ReleaseTimeout(time.Second * 3); err != nil {
			logger.Errorf("event srouce worker pool release timeout %s", err)
		}
		close(s.eventCh)
		close(s.errEventCh)
		s.finalizer()
		logger.Infof("event source finalizer succeed")
	})
}

func unpack(p gopacket.Packet) (*DnsEvent, error) {
	e := &DnsEvent{}
	if p.Metadata() == nil {
		return nil, fmt.Errorf("packet metadata missing")
	}
	e.EventTime = p.Metadata().Timestamp

	ipLayer := p.Layer(layers.LayerTypeIPv4)
	if ipLayer != nil {
		ip, ok := ipLayer.(*layers.IPv4)
		if !ok {
			return nil, fmt.Errorf("packet convert ip layer to ipv4 failed")
		}
		e.SourceIP = ip.SrcIP.String()
		e.DestinationIP = ip.DstIP.String()
	} else {
		ipLayer := p.Layer(layers.LayerTypeIPv6)
		if ipLayer == nil {
			return nil, fmt.Errorf("packet missing ip layer")
		}
		ip, ok := ipLayer.(*layers.IPv6)
		if !ok {
			return e, fmt.Errorf("packet convert ip layer to ipv6 failed")
		}
		e.SourceIP = ip.SrcIP.String()
		e.DestinationIP = ip.DstIP.String()
	}

	udpLayer := p.Layer(layers.LayerTypeUDP)
	if udpLayer == nil {
		return e, fmt.Errorf("packet missing udp layer")
	}
	udp, ok := udpLayer.(*layers.UDP)
	if !ok {
		return e, fmt.Errorf("packet convert udp layer to udp failed")
	}
	e.SourcePort = uint16(udp.SrcPort)
	e.DestinationPort = uint16(udp.DstPort)

	msg := new(dns.Msg)
	if err := msg.Unpack(udp.Payload); err != nil {
		return e, fmt.Errorf("packet unpack to dns msg failed %s", err)
	}

	e.FromMsg(msg)
	return e, nil
}
