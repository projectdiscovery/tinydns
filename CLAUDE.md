# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

### Build and Run
```bash
# Build the binary
make build

# Run with default settings
./tinydns

# Run with YAML configuration
./tinydns -config config.yaml

# Run with custom settings
./tinydns -listen 0.0.0.0:53 -upstream 8.8.8.8:53,1.1.1.1:53 -config config.yaml

# Use built-in DNS providers
./tinydns -provider google      # Use Google DNS
./tinydns -provider alidns      # Use AliDNS (China)
./tinydns -provider cloudflare  # Use Cloudflare DNS
```

### Development
```bash
# Clean up and download dependencies
go mod tidy

# Run tests (currently no tests implemented)
make test

# Update all dependencies
go get -u ./...
go mod tidy
```

## Architecture

### Core Components

1. **tinydns.go**: Main DNS server implementation with YAML config support, multiple record types, and detailed logging

2. **config.go**: YAML configuration parsing and public DNS providers
   - Loads DNS records from YAML files
   - Validates record syntax and required fields
   - Supports multiple record types and actions
   - Contains built-in public DNS server definitions

3. **type.go**: DNS record type definitions
   - Extended to support MX, TXT, CNAME, NS, PTR, SRV records
   - Includes specialized types like MXRecord and SRVRecord

4. **option.go**: Server configuration options
   - Network settings (TCP/UDP, listen address)
   - Cache settings (disk cache enable/disable)
   - Upstream DNS servers
   - YAML config file path

### Request Flow

1. DNS request received → Check YAML config records
2. If not in config → Check in-memory records
3. If not in memory → Check wildcard records
4. If not wildcard → Check disk cache (if enabled)
5. If not cached → Forward to upstream DNS
6. Cache response (if disk cache enabled)
7. Log request details to file

### Key Features

- **Embeddable**: Can be used as a library in other Go applications
- **Configurable**: YAML-based configuration for DNS records
- **Caching**: Hybrid disk/memory caching using projectdiscovery/hmap
- **Logging**: Detailed request/response logging with automatic file rotation
- **Flexible**: Support for resolve (local) or forward (upstream) actions per domain