package main

import (
	"os"
	"os/signal"

	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/tinydns"
)

func main() {
	options := &tinydns.Options{}

	flagSet := goflags.NewFlagSet()
	flagSet.SetDescription(`tinydns - Embeddable dns server.`)

	flagSet.BoolVar(&options.DiskCache, "disk", true, "Use disk cache")
	flagSet.StringVar(&options.ListenAddress, "listen", "127.0.0.1:53", "Listen Address")
	flagSet.StringVar(&options.Net, "net", "udp", "Network (tcp, udp)")
	var upstreamServers goflags.StringSlice
	flagSet.StringSliceVar(&upstreamServers, "upstream", []string{"1.1.1.1:53"}, "Upstream servers", goflags.FileCommaSeparatedStringSliceOptions)

	if err := flagSet.Parse(); err != nil {
		gologger.Fatal().Msgf("Could not parse options: %s\n", err)
	}

	// command line types are converted to standard ones
	options.UpstreamServers = upstreamServers

	tdns, err := tinydns.New(options)
	if err != nil {
		gologger.Fatal().Msgf("Could not create tinydns instance: %s\n", err)
	}
	gologger.Info().Msgf("Listening on: %s:%s\n", options.Net, options.ListenAddress)
	tdns.OnServeDns = func(data tinydns.Info) {
		gologger.Info().Msgf("%s\n", data.Msg)
	}

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
