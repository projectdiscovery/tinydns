package tinydns

import (
	"time"
)

type Options struct {
	ListenAddress   string
	Net             string
	UpstreamServers []string
	DnsRecords      map[string]*DnsRecord
	DiskCache       bool
	TTL             time.Duration
}

var DefaultOptions = Options{
	ListenAddress:   "127.0.0.1:53",
	Net:             "udp",
	UpstreamServers: []string{"8.8.8.8"},
	DiskCache:       true,
}
