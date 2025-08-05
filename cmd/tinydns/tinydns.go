package main

import (
	"os"
	"os/signal"
	"time"

	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/tinydns"
)

func main() {
	options := &tinydns.Options{}

	flagSet := goflags.NewFlagSet()
	flagSet.SetDescription(`tinydns - Embeddable DNS server with YAML configuration support.`)

	flagSet.BoolVar(&options.DiskCache, "disk", true, "Use disk cache")
	flagSet.StringVar(&options.ListenAddress, "listen", "127.0.0.1:53", "Listen Address")
	flagSet.StringVar(&options.Net, "net", "udp", "Network (tcp, udp)")
	flagSet.StringVar(&options.ConfigFile, "config", "", "YAML configuration file path")
	var upstreamServers goflags.StringSlice
	flagSet.StringSliceVar(&upstreamServers, "upstream", []string{"1.1.1.1:53"}, "Upstream servers", goflags.FileCommaSeparatedStringSliceOptions)
	var dnsProvider string
	flagSet.StringVar(&dnsProvider, "provider", "", "Use preset DNS provider (cloudflare, google, quad9, opendns, alidns, dnspod, baidu, cnnic)")
	flagSet.DurationVar(&options.UpstreamTimeout, "timeout", 2*time.Second, "Upstream query timeout")
	flagSet.IntVar(&options.UpstreamRetries, "retries", 2, "Number of upstream query retries")
	flagSet.BoolVar(&options.FallbackResponse, "fallback", false, "Return default response on upstream failure")
	flagSet.StringVar(&options.DefaultA, "default-a", "0.0.0.0", "Default A record for fallback response")
	flagSet.StringVar(&options.DefaultAAAA, "default-aaaa", "::", "Default AAAA record for fallback response")

	if err := flagSet.Parse(); err != nil {
		gologger.Fatal().Msgf("Could not parse options: %s\n", err)
	}

	// command line types are converted to standard ones
	// If provider is specified, use those DNS servers
	if dnsProvider != "" {
		if servers := tinydns.GetPublicDNSServers(dnsProvider); servers != nil {
			options.UpstreamServers = servers
			gologger.Info().Msgf("Using %s DNS servers: %v", dnsProvider, servers)
		} else {
			gologger.Warning().Msgf("Unknown DNS provider '%s', using default", dnsProvider)
			options.UpstreamServers = upstreamServers
		}
	} else {
		options.UpstreamServers = upstreamServers
	}
	options.UseDiskCache = options.DiskCache

	tdns, err := tinydns.New(options)
	if err != nil {
		gologger.Fatal().Msgf("Could not create tinydns instance: %s\n", err)
	}
	gologger.Info().Msgf("TinyDNS server starting on %s (%s)", options.ListenAddress, options.Net)
	if options.ConfigFile != "" {
		gologger.Info().Msgf("Using configuration file: %s", options.ConfigFile)
	}
	gologger.Info().Msgf("Disk cache: %v", options.DiskCache)
	gologger.Info().Msgf("Upstream servers: %v", options.UpstreamServers)

	// Setup graceful exits
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	go func() {
		for range c {
			gologger.Info().Msg("CTRL+C pressed: Shutting down gracefully")
			tdns.Close()
			os.Exit(0)
		}
	}()

	err = tdns.Run()
	if err != nil {
		gologger.Fatal().Msgf("Could not run tinydns server: %s\n", err)
	}
}
