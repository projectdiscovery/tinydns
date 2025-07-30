package tinydns

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// DNSConfig represents the YAML configuration for DNS records
type DNSConfig struct {
	Records  []DNSRecord     `yaml:"records"`
	Upstream UpstreamConfig  `yaml:"upstream,omitempty"`
}

// UpstreamConfig represents upstream DNS server configuration
type UpstreamConfig struct {
	Timeout          string   `yaml:"timeout,omitempty"`          // Timeout duration (e.g., "2s", "500ms")
	Retries          int      `yaml:"retries,omitempty"`          // Number of retries
	FallbackResponse bool     `yaml:"fallback_response,omitempty"` // Return default response on failure
	DefaultA         string   `yaml:"default_a,omitempty"`         // Default A record IP
	DefaultAAAA      string   `yaml:"default_aaaa,omitempty"`      // Default AAAA record IP
	Servers          []string `yaml:"servers,omitempty"`          // Override upstream servers
}

// DNSRecord represents a single DNS record configuration
type DNSRecord struct {
	Domain      string   `yaml:"domain"`
	Type        string   `yaml:"type"`
	Value       string   `yaml:"value"`
	Values      []string `yaml:"values,omitempty"`      // For multiple values (e.g., multiple A records)
	TTL         uint32   `yaml:"ttl,omitempty"`         // Time to live
	Priority    uint16   `yaml:"priority,omitempty"`    // For MX records
	Weight      uint16   `yaml:"weight,omitempty"`      // For SRV records
	Port        uint16   `yaml:"port,omitempty"`        // For SRV records
	Target      string   `yaml:"target,omitempty"`      // For SRV records
	Action      string   `yaml:"action,omitempty"`      // "resolve" or "forward", default is "resolve"
}

// LoadConfig loads DNS configuration from a YAML file
func LoadConfig(filename string) (*DNSConfig, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var config DNSConfig
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse YAML config: %w", err)
	}

	// Validate and normalize configuration
	for i := range config.Records {
		record := &config.Records[i]
		
		// Normalize type to uppercase
		record.Type = strings.ToUpper(record.Type)
		
		// Set default action if not specified
		if record.Action == "" {
			record.Action = "resolve"
		}
		
		// Set default TTL if not specified
		if record.TTL == 0 {
			record.TTL = 300 // 5 minutes default
		}
		
		// Validate action
		if record.Action != "resolve" && record.Action != "forward" {
			return nil, fmt.Errorf("invalid action '%s' for record %s, must be 'resolve' or 'forward'", record.Action, record.Domain)
		}
		
		// Validate required fields based on record type (only for "resolve" action)
		if record.Action == "resolve" {
			switch record.Type {
			case "A", "AAAA":
				if record.Value == "" && len(record.Values) == 0 {
					return nil, fmt.Errorf("A/AAAA record for %s with action 'resolve' must have 'value' or 'values' field", record.Domain)
				}
			case "MX":
				if record.Target == "" {
					return nil, fmt.Errorf("MX record for %s with action 'resolve' must have 'target' field", record.Domain)
				}
				if record.Priority == 0 {
					record.Priority = 10 // Default priority
				}
			case "SRV":
				if record.Target == "" {
					return nil, fmt.Errorf("SRV record for %s with action 'resolve' must have 'target' field", record.Domain)
				}
				if record.Port == 0 {
					return nil, fmt.Errorf("SRV record for %s with action 'resolve' must have 'port' field", record.Domain)
				}
			case "TXT", "CNAME", "NS", "PTR":
				if record.Value == "" {
					return nil, fmt.Errorf("%s record for %s with action 'resolve' must have 'value' field", record.Type, record.Domain)
				}
			default:
				return nil, fmt.Errorf("unsupported record type '%s' for %s", record.Type, record.Domain)
			}
		}
	}

	return &config, nil
}

// Common public DNS servers
var PublicDNSServers = map[string][]string{
	"cloudflare": {
		"1.1.1.1:53",
		"1.0.0.1:53",
		"2606:4700:4700::1111",
		"2606:4700:4700::1001",
	},
	"google": {
		"8.8.8.8:53",
		"8.8.4.4:53",
		"2001:4860:4860::8888",
		"2001:4860:4860::8844",
	},
	"quad9": {
		"9.9.9.9:53",
		"149.112.112.112:53",
		"2620:fe::fe",
		"2620:fe::9",
	},
	"opendns": {
		"208.67.222.222:53",
		"208.67.220.220:53",
		"2620:119:35::35",
		"2620:119:53::53",
	},
	"alidns": {
		"223.5.5.5:53",
		"223.6.6.6:53",
		"2400:3200::1",
		"2400:3200:baba::1",
	},
	"dnspod": {
		"119.29.29.29:53",
		"119.28.28.28:53",
	},
	"baidu": {
		"180.76.76.76:53",
	},
	"cnnic": {
		"1.2.4.8:53",
		"210.2.4.8:53",
	},
}

// GetPublicDNSServers returns DNS servers for the specified provider
func GetPublicDNSServers(provider string) []string {
	if servers, ok := PublicDNSServers[provider]; ok {
		return servers
	}
	return nil
}

// GetAllPublicDNSServers returns all available public DNS servers
func GetAllPublicDNSServers() []string {
	var all []string
	for _, servers := range PublicDNSServers {
		all = append(all, servers...)
	}
	return all
}