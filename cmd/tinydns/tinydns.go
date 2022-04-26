package main

import (
	"flag"
	"os"
	"os/signal"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/tinydns"
)

func main() {
	options := &tinydns.Options{}

	flag.BoolVar(&options.DiskCache, "disk", true, "Use disk cache")
	flag.StringVar(&options.ListenAddress, "listen", "127.0.0.1:53", "Listen Address")
	flag.StringVar(&options.Net, "net", "udp", "Network (tcp, udp)")
	flag.Parse()

	options.UpstreamServers = []string{"8.8.8.8:53"}

	tdns, err := tinydns.New(options)
	if err != nil {
		gologger.Fatal().Msgf("Could not create tinydns instance: %s\n", err)
	}
	gologger.Info().Msgf("Listening on: %s:%s\n", options.Net, options.ListenAddress)

	// Setup graceful exits
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	go func() {
		for range c {
			gologger.Info().Msgf("CTRL+C pressed: Exiting\n")
			tdns.Close()
			os.Exit(1)
		}
	}()

	err = tdns.Run()
	if err != nil {
		gologger.Fatal().Msgf("Could not run tinydns server: %s\n", err)
	}
}
