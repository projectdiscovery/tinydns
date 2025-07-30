package tinydns

type DnsRecord struct {
	A     []string
	AAAA  []string
	MX    []MXRecord
	TXT   []string
	CNAME string
	NS    []string
	PTR   []string
	SRV   []SRVRecord
}

type MXRecord struct {
	Priority uint16
	Target   string
}

type SRVRecord struct {
	Priority uint16
	Weight   uint16
	Port     uint16
	Target   string
}
