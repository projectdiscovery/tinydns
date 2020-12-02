package tinydns

import (
	"net"
	"strings"

	"github.com/miekg/dns"
)

type tinydnshandler struct {
	fallbackDNS     string
	DomainToAddress map[string]string
}

func (t *tinydnshandler) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	domain := r.Question[0].Name
	domainlookup := strings.TrimSuffix(domain, ".")
	switch r.Question[0].Qtype {
	case dns.TypeA:
		// try to lookup hardcoded one
		if address, ok := t.DomainToAddress[domainlookup]; ok {
			w.WriteMsg(buildAnswer(r, domain, address))
		} else if address, ok = t.DomainToAddress["*"]; ok {
			// wildcard
			w.WriteMsg(buildAnswer(r, domain, address))
		} else if t.fallbackDNS != "" {
			// upstream
			if msg, err := dns.Exchange(r, t.fallbackDNS); err == nil {
				w.WriteMsg(msg)
			}
		}
	}
	w.WriteMsg(buildAnswer(r, domain, ""))
}

func buildAnswer(r *dns.Msg, domain, address string) *dns.Msg {
	msg := dns.Msg{}
	msg.SetReply(r)
	msg.Authoritative = true
	if address != "" {
		msg.Answer = append(msg.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: domain, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   net.ParseIP(address),
		})
	}
	return &msg
}

type OptionsTinyDNS struct {
	ListenAddress       string
	Net                 string
	FallbackDNSResolver string
	DomainToAddress     map[string]string
}

type TinyDNS struct {
	options *OptionsTinyDNS
	server  *dns.Server
}

func (t *TinyDNS) Run() {
	t.server.ListenAndServe()
}

func NewTinyDNS(options *OptionsTinyDNS) *TinyDNS {
	srv := &dns.Server{
		Addr: options.ListenAddress,
		Net:  options.Net,
	}
	srv.Handler = &tinydnshandler{
		fallbackDNS:     options.FallbackDNSResolver,
		DomainToAddress: options.DomainToAddress,
	}
	tinydns := &TinyDNS{
		options: options,
		server:  srv,
	}

	return tinydns
}
