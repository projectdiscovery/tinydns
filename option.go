package tinydns

import (
	"time"
)

type Options struct {
	ListenAddress    string
	Net              string
	UpstreamServers  []string
	DnsRecords       map[string]*DnsRecord
	DiskCache        bool
	UseDiskCache     bool          // Alias for DiskCache for compatibility
	TTL              time.Duration
	ConfigFile       string        // Path to YAML configuration file
	UpstreamTimeout  time.Duration // Timeout for upstream queries
	UpstreamRetries  int           // Number of retries for upstream queries
	FallbackResponse bool          // Return default response on upstream failure
	DefaultA         string        // Default A record on upstream failure
	DefaultAAAA      string        // Default AAAA record on upstream failure
}

var DefaultOptions = Options{
	ListenAddress:    "127.0.0.1:53",
	Net:              "udp",
	UpstreamServers:  []string{"1.1.1.1:53"},
	DiskCache:        true,
	UseDiskCache:     true,
	UpstreamTimeout:  2 * time.Second,
	UpstreamRetries:  2,
	FallbackResponse: false,
	DefaultA:         "0.0.0.0",
	DefaultAAAA:      "::",
}
