package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"strings"

	"github.com/google/gopacket/pcap"

	"github.com/hiwyw/dnscap-tool/app"
	"github.com/hiwyw/dnscap-tool/app/config"
	"github.com/hiwyw/dnscap-tool/app/logger"
	"github.com/hiwyw/dnscap-tool/app/pkg/signal"
)

var (
	genConfig    bool
	printVersion bool
	showDevices  bool

	configFile string
	build      = ""
	version    = ""
)

func main() {
	flag.StringVar(&configFile, "config", "config.yaml", "config file")
	flag.BoolVar(&genConfig, "gen", false, "gen demo config file")
	flag.BoolVar(&printVersion, "version", false, "print version")
	flag.BoolVar(&showDevices, "devices", false, "print all devices")
	flag.Parse()

	if printVersion {
		log.Printf("build at %s version %s", build, version)
		return
	}

	if genConfig {
		config.Generate(configFile)
		log.Printf("gen demo config %s succeed", configFile)
		return
	}

	if showDevices {
		ifs, err := pcap.FindAllDevs()
		if err != nil {
			log.Printf("find all devices failed %s", err)
		}

		log.Println("Devices:")
		for _, i := range ifs {
			log.Println("#################")
			log.Printf("Name------>%s", i.Name)
			log.Printf("Description------>%s", i.Description)

			var ips []string
			for _, address := range i.Addresses {
				ips = append(ips, fmt.Sprintf("%s %s", address.IP.String(), address.Netmask.String()))
			}
			log.Printf("Addresses------>%s", strings.Join(ips, " "))
			log.Println()
		}
		return
	}

	cfg := config.Load(configFile)
	if cfg.EnableDebug {
		logger.SetDebug()
	}

	a := app.NewApp(cfg)

	signal.WithSignalEx(context.Background(), func() {
		a.Close()
	})

	a.Run()
}
