# TinyDNS

An embeddable DNS server written in Go with YAML configuration support, caching, and flexible upstream handling.

## Features

- **Embeddable**: Can be used as a library in Go applications or run as a standalone server
- **YAML Configuration**: Define DNS records and upstream behavior via YAML files
- **Multiple Record Types**: Supports A, AAAA, MX, TXT, CNAME, NS, PTR, SRV records
- **Flexible Resolution**: Choose to resolve locally or forward to upstream DNS servers
- **Built-in Public DNS**: Pre-configured popular DNS providers (Google, Cloudflare, etc.)
- **Advanced Caching**: Hybrid memory/disk caching for improved performance
- **Retry & Fallback**: Configurable retry logic with fallback responses
- **Detailed Logging**: Comprehensive request/response logging with automatic file rotation

## Installation

```bash
# Clone the repository
git clone https://github.com/projectdiscovery/tinydns.git
cd tinydns

# Build the binary
make build

# Or install directly
go install github.com/projectdiscovery/tinydns/cmd/tinydns@latest
```

## Quick Start

```bash
# Run with default settings (Cloudflare DNS)
./tinydns

# Use a specific DNS provider
./tinydns -provider google

# Use with YAML configuration
./tinydns -config config.yaml

# Listen on a different port
./tinydns -listen 127.0.0.1:5353
```

## Command Line Options

```
-listen string      Listen address (default "127.0.0.1:53")
-net string         Network protocol: tcp, udp (default "udp")
-disk               Enable disk cache (default true)
-config string      YAML configuration file path

# Upstream DNS Options
-upstream strings   Upstream DNS servers (default ["1.1.1.1:53"])
-provider string    Use preset DNS provider (see below)
-timeout duration   Upstream query timeout (default 2s)
-retries int        Number of upstream retries (default 2)
-fallback           Return default response on upstream failure
-default-a string   Default A record for fallback (default "0.0.0.0")
-default-aaaa string Default AAAA record for fallback (default "::")
```

## Built-in DNS Providers

Use the `-provider` flag to quickly configure popular DNS services:

### International Providers
- `cloudflare` - Cloudflare DNS (1.1.1.1, 1.0.0.1) - Privacy-focused
- `google` - Google Public DNS (8.8.8.8, 8.8.4.4)
- `quad9` - Quad9 DNS (9.9.9.9) - Security-focused, blocks malicious domains
- `opendns` - OpenDNS (208.67.222.222) - Content filtering available

### Regional Providers (China)
- `alidns` - Alibaba DNS (223.5.5.5, 223.6.6.6)
- `dnspod` - DNSPod/Tencent DNS (119.29.29.29, 119.28.28.28)
- `baidu` - Baidu DNS (180.76.76.76)
- `cnnic` - CNNIC SDNS (1.2.4.8, 210.2.4.8)

Example:
```bash
# Use Google DNS with custom timeout
./tinydns -provider google -timeout 3s -retries 5

# Use AliDNS for users in China
./tinydns -provider alidns
```

## YAML Configuration

Create a YAML file to define DNS records and upstream behavior. See `config.example.yaml` for a complete example.

### Basic Structure

```yaml
# Optional: Configure upstream DNS behavior
upstream:
  timeout: "3s"           # Query timeout
  retries: 3              # Number of retries
  fallback_response: true # Return default on failure
  default_a: "127.0.0.1"  # Default A record
  default_aaaa: "::1"     # Default AAAA record
  servers:                # Override upstream servers
    - "8.8.8.8:53"
    - "1.1.1.1:53"

# DNS Records
records:
  # Local resolution
  - domain: example.local
    type: A
    value: 192.168.1.100
    ttl: 300
    action: resolve

  # Forward to upstream
  - domain: google.com
    type: A
    action: forward

  # Wildcard domain
  - domain: "*.internal.local"
    type: A
    value: 10.0.0.1
    ttl: 60
    action: resolve
```

### Supported Record Types

| Type | Description | Required Fields |
|------|-------------|-----------------|
| A | IPv4 address | `value` or `values` |
| AAAA | IPv6 address | `value` or `values` |
| MX | Mail server | `target`, `priority` |
| TXT | Text record | `value` |
| CNAME | Canonical name | `value` |
| NS | Name server | `value` |
| PTR | Pointer (reverse DNS) | `value` |
| SRV | Service record | `target`, `priority`, `weight`, `port` |

### Actions

- `resolve` - Return the configured response (requires value fields)
- `forward` - Forward query to upstream DNS servers (no value fields needed)

## Advanced Features

### Upstream Configuration

Control how TinyDNS handles upstream DNS queries:

```yaml
upstream:
  timeout: "5s"           # Wait up to 5 seconds for response
  retries: 3              # Try 3 different servers
  fallback_response: true # Return default IP on failure
  default_a: "127.0.0.1"  # Fallback A record
  default_aaaa: "::1"     # Fallback AAAA record
```

This ensures your DNS service remains responsive even when upstream servers are unavailable.

### Logging

Logs are automatically saved to `logs/tinydns_YYYYMMDD_HHMMSS.log` with:
- Request details (type, domain, client IP)
- Response source (config, cache, upstream)
- Response times and retry attempts
- Errors and warnings

### Use as a Library

```go
package main

import (
    "github.com/projectdiscovery/tinydns"
)

func main() {
    options := &tinydns.Options{
        ListenAddress: "127.0.0.1:53",
        Net: "udp",
        UpstreamServers: []string{"8.8.8.8:53"},
    }
    
    // Add custom DNS records
    options.DnsRecords = map[string]*tinydns.DnsRecord{
        "example.local": {
            A: []string{"127.0.0.1"},
        },
    }
    
    server, err := tinydns.New(options)
    if err != nil {
        panic(err)
    }
    
    // Start the server
    if err := server.Run(); err != nil {
        panic(err)
    }
}
```

## Examples

### Block Ads/Trackers
```yaml
records:
  - domain: doubleclick.net
    type: A
    value: 0.0.0.0
    ttl: 0
    action: resolve
```

### Internal Network
```yaml
records:
  - domain: "*.corp.local"
    type: A
    value: 10.0.0.1
    ttl: 300
    action: resolve
    
  - domain: mail.corp.local
    type: MX
    target: exchange.corp.local.
    priority: 10
    ttl: 3600
    action: resolve
```

### Development Environment
```yaml
records:
  - domain: "*.test"
    type: A
    value: 127.0.0.1
    ttl: 0
    action: resolve
    
  - domain: api.dev
    type: CNAME
    value: localhost.
    ttl: 0
    action: resolve
```

## Building from Source

```bash
# Clone the repository
git clone https://github.com/projectdiscovery/tinydns.git
cd tinydns

# Download dependencies
go mod download

# Build
make build

# Run tests (if available)
make test
```

## License

TinyDNS is distributed under the MIT License.