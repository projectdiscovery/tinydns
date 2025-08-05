package tinydns

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/hmap/store/hybrid"
	sliceutil "github.com/projectdiscovery/utils/slice"
)

type TinyDNS struct {
	options    *Options
	server     *dns.Server
	hm         *hybrid.HybridMap
	OnServeDns func(data Info)
	config     *DNSConfig
	logFile    *os.File
}

type Info struct {
	Domain       string
	Operation    string
	Wildcard     bool
	Msg          string
	Upstream     string
	RecordType   string
	ClientIP     string
	Timestamp    time.Time
	ResponseTime time.Duration
}

func New(options *Options) (*TinyDNS, error) {
	hm, err := hybrid.New(hybrid.DefaultDiskOptions)
	if err != nil {
		return nil, err
	}

	tinydns := &TinyDNS{
		options: options,
		hm:      hm,
	}

	// Initialize file logging
	if err := tinydns.initFileLogging(); err != nil {
		return nil, fmt.Errorf("failed to initialize file logging: %w", err)
	}

	// Load YAML configuration if provided
	if options.ConfigFile != "" {
		config, err := LoadConfig(options.ConfigFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load config: %w", err)
		}
		tinydns.config = config
		
		// Apply upstream configuration from YAML
		if config.Upstream.Timeout != "" {
			if duration, err := time.ParseDuration(config.Upstream.Timeout); err == nil {
				options.UpstreamTimeout = duration
			}
		}
		if config.Upstream.Retries > 0 {
			options.UpstreamRetries = config.Upstream.Retries
		}
		if config.Upstream.FallbackResponse {
			options.FallbackResponse = true
		}
		if config.Upstream.DefaultA != "" {
			options.DefaultA = config.Upstream.DefaultA
		}
		if config.Upstream.DefaultAAAA != "" {
			options.DefaultAAAA = config.Upstream.DefaultAAAA
		}
		if len(config.Upstream.Servers) > 0 {
			options.UpstreamServers = config.Upstream.Servers
		}
		
		gologger.Info().Msgf("Loaded %d DNS records from config file", len(config.Records))
		tinydns.logToFile(fmt.Sprintf("Loaded %d DNS records from config file: %s", len(config.Records), options.ConfigFile))
	}

	srv := &dns.Server{
		Addr:    options.ListenAddress,
		Net:     options.Net,
		Handler: tinydns,
	}
	tinydns.server = srv

	return tinydns, nil
}

func (t *TinyDNS) initFileLogging() error {
	// Create logs directory
	logDir := "logs"
	if err := os.MkdirAll(logDir, 0755); err != nil {
		return fmt.Errorf("failed to create log directory: %w", err)
	}

	// Create log file with timestamp
	timestamp := time.Now().Format("20060102_150405")
	logFileName := fmt.Sprintf("tinydns_%s.log", timestamp)
	logPath := filepath.Join(logDir, logFileName)

	file, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return fmt.Errorf("failed to create log file: %w", err)
	}

	t.logFile = file
	t.logToFile(fmt.Sprintf("TinyDNS started at %s", time.Now().Format(time.RFC3339)))
	t.logToFile(fmt.Sprintf("Listening on %s (%s)", t.options.ListenAddress, t.options.Net))
	
	return nil
}

func (t *TinyDNS) logToFile(msg string) {
	if t.logFile != nil {
		timestamp := time.Now().Format("2006-01-02 15:04:05.000")
		fmt.Fprintf(t.logFile, "[%s] %s\n", timestamp, msg)
		t.logFile.Sync()
	}
}

func (t *TinyDNS) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	startTime := time.Now()
	clientIP := w.RemoteAddr().String()
	
	if len(r.Question) == 0 {
		return
	}

	question := r.Question[0]
	domain := question.Name
	domainLookup := strings.TrimSuffix(domain, ".")
	recordType := dns.TypeToString[question.Qtype]

	// Log incoming request
	t.logToFile(fmt.Sprintf("REQUEST: [%s] %s %s from %s", recordType, domainLookup, dns.OpcodeToString[r.Opcode], clientIP))
	gologger.Info().Msgf("DNS request: %s %s from %s", recordType, domainLookup, clientIP)

	// Check YAML configuration first
	if t.config != nil {
		for _, record := range t.config.Records {
			if matchesDomain(domainLookup, record.Domain) && record.Type == recordType {
				if record.Action == "forward" {
					// Forward to upstream
					t.forwardToUpstream(w, r, domainLookup, clientIP, recordType, startTime)
					return
				}
				// Resolve locally
				msg := t.createResponseFromConfig(r, domain, record, question.Qtype)
				if msg != nil {
					w.WriteMsg(msg)
					responseTime := time.Since(startTime)
					t.logToFile(fmt.Sprintf("RESPONSE: [%s] %s resolved from config in %v", recordType, domainLookup, responseTime))
					return
				}
			}
		}
	}

	// Handle based on record type
	switch question.Qtype {
	case dns.TypeA, dns.TypeAAAA, dns.TypeMX, dns.TypeTXT, dns.TypeSRV, dns.TypeCNAME, dns.TypeNS, dns.TypePTR:
		t.handleDNSQuery(w, r, domainLookup, clientIP, recordType, question.Qtype, startTime)
	default:
		// Forward unsupported types to upstream
		t.forwardToUpstream(w, r, domainLookup, clientIP, recordType, startTime)
	}
}

func (t *TinyDNS) handleDNSQuery(w dns.ResponseWriter, r *dns.Msg, domainLookup, clientIP, recordType string, qtype uint16, startTime time.Time) {
	domain := r.Question[0].Name

	// Check hardcoded records
	if dnsRecord, ok := t.options.DnsRecords[domainLookup]; ok {
		msg := t.createResponseFromDnsRecord(r, domain, dnsRecord, qtype)
		w.WriteMsg(msg)
		responseTime := time.Since(startTime)
		t.logToFile(fmt.Sprintf("RESPONSE: [%s] %s resolved from memory in %v", recordType, domainLookup, responseTime))
		return
	}

	// Check wildcard
	if dnsRecord, ok := t.options.DnsRecords["*"]; ok {
		msg := t.createResponseFromDnsRecord(r, domain, dnsRecord, qtype)
		w.WriteMsg(msg)
		responseTime := time.Since(startTime)
		t.logToFile(fmt.Sprintf("RESPONSE: [%s] %s resolved from wildcard in %v", recordType, domainLookup, responseTime))
		return
	}

	// Check cache
	if t.options.UseDiskCache {
		if dnsRecordBytes, ok := t.hm.Get(domain + recordType); ok {
			dnsRecord := &DnsRecord{}
			err := gob.NewDecoder(bytes.NewReader(dnsRecordBytes)).Decode(dnsRecord)
			if err == nil {
				msg := t.createResponseFromDnsRecord(r, domain, dnsRecord, qtype)
				w.WriteMsg(msg)
				responseTime := time.Since(startTime)
				t.logToFile(fmt.Sprintf("RESPONSE: [%s] %s resolved from cache in %v", recordType, domainLookup, responseTime))
				return
			}
		}
	}

	// Forward to upstream
	t.forwardToUpstream(w, r, domainLookup, clientIP, recordType, startTime)
}

func (t *TinyDNS) forwardToUpstream(w dns.ResponseWriter, r *dns.Msg, domainLookup, clientIP, recordType string, startTime time.Time) {
	if len(t.options.UpstreamServers) == 0 {
		t.sendFallbackOrEmpty(w, r, domainLookup, recordType, startTime, "no upstream servers configured")
		return
	}

	// Create DNS client with timeout
	client := &dns.Client{
		Net:     t.options.Net,
		Timeout: t.options.UpstreamTimeout,
	}

	var lastErr error
	retries := t.options.UpstreamRetries
	if retries <= 0 {
		retries = 1
	}

	// Try multiple times with different upstream servers
	for attempt := 0; attempt < retries; attempt++ {
		upstreamServer := sliceutil.PickRandom(t.options.UpstreamServers)
		t.logToFile(fmt.Sprintf("FORWARD: [%s] %s to upstream %s from %s (attempt %d/%d)", recordType, domainLookup, upstreamServer, clientIP, attempt+1, retries))

		msg, _, err := client.Exchange(r, upstreamServer)
		if err == nil && msg != nil {
			// Success
			w.WriteMsg(msg)
			responseTime := time.Since(startTime)
			t.logToFile(fmt.Sprintf("RESPONSE: [%s] %s resolved from upstream %s in %v with %d answers", recordType, domainLookup, upstreamServer, responseTime, len(msg.Answer)))
			
			// Cache the response
			if t.options.UseDiskCache && len(msg.Answer) > 0 {
				dnsRecord := extractDnsRecord(msg)
				var dnsRecordBytes bytes.Buffer
				if err := gob.NewEncoder(&dnsRecordBytes).Encode(dnsRecord); err == nil {
					t.hm.Set(r.Question[0].Name+recordType, dnsRecordBytes.Bytes())
					t.logToFile(fmt.Sprintf("CACHE: [%s] %s saved to cache", recordType, domainLookup))
				}
			}
			return
		}

		lastErr = err
		t.logToFile(fmt.Sprintf("ERROR: [%s] %s upstream query failed on %s: %v", recordType, domainLookup, upstreamServer, err))
		
		// Wait a bit before retry (except for last attempt)
		if attempt < retries-1 {
			time.Sleep(100 * time.Millisecond)
		}
	}

	// All retries failed
	responseTime := time.Since(startTime)
	t.logToFile(fmt.Sprintf("ERROR: [%s] %s all upstream queries failed after %d attempts (took %v): %v", recordType, domainLookup, retries, responseTime, lastErr))
	gologger.Error().Msgf("All upstream queries failed for %s after %d attempts: %v", domainLookup, retries, lastErr)
	
	// Send fallback response or empty
	t.sendFallbackOrEmpty(w, r, domainLookup, recordType, startTime, fmt.Sprintf("upstream failed: %v", lastErr))
}

func (t *TinyDNS) sendFallbackOrEmpty(w dns.ResponseWriter, r *dns.Msg, domainLookup, recordType string, startTime time.Time, reason string) {
	msg := new(dns.Msg)
	msg.SetReply(r)
	
	if t.options.FallbackResponse && len(r.Question) > 0 {
		domain := r.Question[0].Name
		qtype := r.Question[0].Qtype
		
		switch qtype {
		case dns.TypeA:
			if t.options.DefaultA != "" {
				rr := &dns.A{
					Hdr: dns.RR_Header{Name: domain, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 0},
					A:   net.ParseIP(t.options.DefaultA),
				}
				msg.Answer = append(msg.Answer, rr)
			}
		case dns.TypeAAAA:
			if t.options.DefaultAAAA != "" {
				rr := &dns.AAAA{
					Hdr:  dns.RR_Header{Name: domain, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 0},
					AAAA: net.ParseIP(t.options.DefaultAAAA),
				}
				msg.Answer = append(msg.Answer, rr)
			}
		}
		
		if len(msg.Answer) > 0 {
			responseTime := time.Since(startTime)
			t.logToFile(fmt.Sprintf("RESPONSE: [%s] %s returned fallback response (%s) in %v", recordType, domainLookup, reason, responseTime))
		} else {
			responseTime := time.Since(startTime)
			t.logToFile(fmt.Sprintf("RESPONSE: [%s] %s returned empty response (%s) in %v", recordType, domainLookup, reason, responseTime))
		}
	} else {
		responseTime := time.Since(startTime)
		t.logToFile(fmt.Sprintf("RESPONSE: [%s] %s returned empty response (%s) in %v", recordType, domainLookup, reason, responseTime))
	}
	
	w.WriteMsg(msg)
}

func (t *TinyDNS) createResponseFromConfig(r *dns.Msg, domain string, record DNSRecord, qtype uint16) *dns.Msg {
	msg := new(dns.Msg)
	msg.SetReply(r)
	msg.Authoritative = true

	switch qtype {
	case dns.TypeA:
		if record.Value != "" {
			rr := &dns.A{
				Hdr: dns.RR_Header{Name: domain, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: record.TTL},
				A:   net.ParseIP(record.Value),
			}
			msg.Answer = append(msg.Answer, rr)
		}
		for _, ip := range record.Values {
			rr := &dns.A{
				Hdr: dns.RR_Header{Name: domain, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: record.TTL},
				A:   net.ParseIP(ip),
			}
			msg.Answer = append(msg.Answer, rr)
		}
	case dns.TypeAAAA:
		if record.Value != "" {
			rr := &dns.AAAA{
				Hdr:  dns.RR_Header{Name: domain, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: record.TTL},
				AAAA: net.ParseIP(record.Value),
			}
			msg.Answer = append(msg.Answer, rr)
		}
		for _, ip := range record.Values {
			rr := &dns.AAAA{
				Hdr:  dns.RR_Header{Name: domain, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: record.TTL},
				AAAA: net.ParseIP(ip),
			}
			msg.Answer = append(msg.Answer, rr)
		}
	case dns.TypeMX:
		rr := &dns.MX{
			Hdr:        dns.RR_Header{Name: domain, Rrtype: dns.TypeMX, Class: dns.ClassINET, Ttl: record.TTL},
			Preference: record.Priority,
			Mx:         record.Target,
		}
		msg.Answer = append(msg.Answer, rr)
	case dns.TypeTXT:
		rr := &dns.TXT{
			Hdr: dns.RR_Header{Name: domain, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: record.TTL},
			Txt: []string{record.Value},
		}
		msg.Answer = append(msg.Answer, rr)
	case dns.TypeSRV:
		rr := &dns.SRV{
			Hdr:      dns.RR_Header{Name: domain, Rrtype: dns.TypeSRV, Class: dns.ClassINET, Ttl: record.TTL},
			Priority: record.Priority,
			Weight:   record.Weight,
			Port:     record.Port,
			Target:   record.Target,
		}
		msg.Answer = append(msg.Answer, rr)
	case dns.TypeCNAME:
		rr := &dns.CNAME{
			Hdr:    dns.RR_Header{Name: domain, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: record.TTL},
			Target: record.Value,
		}
		msg.Answer = append(msg.Answer, rr)
	case dns.TypeNS:
		rr := &dns.NS{
			Hdr: dns.RR_Header{Name: domain, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: record.TTL},
			Ns:  record.Value,
		}
		msg.Answer = append(msg.Answer, rr)
	case dns.TypePTR:
		rr := &dns.PTR{
			Hdr: dns.RR_Header{Name: domain, Rrtype: dns.TypePTR, Class: dns.ClassINET, Ttl: record.TTL},
			Ptr: record.Value,
		}
		msg.Answer = append(msg.Answer, rr)
	}

	return msg
}

func (t *TinyDNS) createResponseFromDnsRecord(r *dns.Msg, domain string, dnsRecord *DnsRecord, qtype uint16) *dns.Msg {
	msg := new(dns.Msg)
	msg.SetReply(r)
	msg.Authoritative = true

	switch qtype {
	case dns.TypeA:
		for _, a := range dnsRecord.A {
			rr := &dns.A{
				Hdr: dns.RR_Header{Name: domain, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
				A:   net.ParseIP(a),
			}
			msg.Answer = append(msg.Answer, rr)
		}
	case dns.TypeAAAA:
		for _, aaaa := range dnsRecord.AAAA {
			rr := &dns.AAAA{
				Hdr:  dns.RR_Header{Name: domain, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 60},
				AAAA: net.ParseIP(aaaa),
			}
			msg.Answer = append(msg.Answer, rr)
		}
	case dns.TypeMX:
		for _, mx := range dnsRecord.MX {
			rr := &dns.MX{
				Hdr:        dns.RR_Header{Name: domain, Rrtype: dns.TypeMX, Class: dns.ClassINET, Ttl: 60},
				Preference: mx.Priority,
				Mx:         mx.Target,
			}
			msg.Answer = append(msg.Answer, rr)
		}
	case dns.TypeTXT:
		for _, txt := range dnsRecord.TXT {
			rr := &dns.TXT{
				Hdr: dns.RR_Header{Name: domain, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60},
				Txt: []string{txt},
			}
			msg.Answer = append(msg.Answer, rr)
		}
	case dns.TypeSRV:
		for _, srv := range dnsRecord.SRV {
			rr := &dns.SRV{
				Hdr:      dns.RR_Header{Name: domain, Rrtype: dns.TypeSRV, Class: dns.ClassINET, Ttl: 60},
				Priority: srv.Priority,
				Weight:   srv.Weight,
				Port:     srv.Port,
				Target:   srv.Target,
			}
			msg.Answer = append(msg.Answer, rr)
		}
	case dns.TypeCNAME:
		if dnsRecord.CNAME != "" {
			rr := &dns.CNAME{
				Hdr:    dns.RR_Header{Name: domain, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 60},
				Target: dnsRecord.CNAME,
			}
			msg.Answer = append(msg.Answer, rr)
		}
	case dns.TypeNS:
		for _, ns := range dnsRecord.NS {
			rr := &dns.NS{
				Hdr: dns.RR_Header{Name: domain, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 60},
				Ns:  ns,
			}
			msg.Answer = append(msg.Answer, rr)
		}
	case dns.TypePTR:
		for _, ptr := range dnsRecord.PTR {
			rr := &dns.PTR{
				Hdr: dns.RR_Header{Name: domain, Rrtype: dns.TypePTR, Class: dns.ClassINET, Ttl: 60},
				Ptr: ptr,
			}
			msg.Answer = append(msg.Answer, rr)
		}
	}

	return msg
}

func extractDnsRecord(msg *dns.Msg) *DnsRecord {
	dnsRecord := &DnsRecord{}
	for _, answer := range msg.Answer {
		switch rr := answer.(type) {
		case *dns.A:
			dnsRecord.A = append(dnsRecord.A, rr.A.String())
		case *dns.AAAA:
			dnsRecord.AAAA = append(dnsRecord.AAAA, rr.AAAA.String())
		case *dns.MX:
			dnsRecord.MX = append(dnsRecord.MX, MXRecord{
				Priority: rr.Preference,
				Target:   rr.Mx,
			})
		case *dns.TXT:
			dnsRecord.TXT = append(dnsRecord.TXT, strings.Join(rr.Txt, ""))
		case *dns.SRV:
			dnsRecord.SRV = append(dnsRecord.SRV, SRVRecord{
				Priority: rr.Priority,
				Weight:   rr.Weight,
				Port:     rr.Port,
				Target:   rr.Target,
			})
		case *dns.CNAME:
			dnsRecord.CNAME = rr.Target
		case *dns.NS:
			dnsRecord.NS = append(dnsRecord.NS, rr.Ns)
		case *dns.PTR:
			dnsRecord.PTR = append(dnsRecord.PTR, rr.Ptr)
		}
	}
	return dnsRecord
}

func matchesDomain(query, pattern string) bool {
	if pattern == "*" {
		return true
	}
	if strings.HasPrefix(pattern, "*.") {
		suffix := strings.TrimPrefix(pattern, "*")
		return strings.HasSuffix(query, suffix)
	}
	return query == pattern
}

func (t *TinyDNS) Run() error {
	gologger.Info().Msgf("Starting TinyDNS server on %s (%s)", t.options.ListenAddress, t.options.Net)
	t.logToFile("TinyDNS server started successfully")
	return t.server.ListenAndServe()
}

func (t *TinyDNS) Close() {
	t.logToFile("TinyDNS server shutting down")
	if t.logFile != nil {
		t.logFile.Close()
	}
	t.hm.Close()
}
