package netservice

const MaxDHCPv4PoolAddresses = 1 << 16

type DHCPv4Reservation struct {
	MACAddress  string
	IPv4Address string
	Remark      string
}

type DHCPv4Config struct {
	Bridge          string
	UplinkInterface string
	ServerCIDR      string
	ServerIP        string
	Gateway         string
	PoolStart       string
	PoolEnd         string
	DNSServers      []string
	Reservations    []DHCPv4Reservation
}

type DHCPv4RuntimeState struct {
	Status     string
	Detail     string
	ReplyCount uint64
}

type RAConfig struct {
	TargetInterface string
	Managed         bool
	Prefixes        []string
	Routes          []string
	DNSServers      []string
}

type DHCPv6Config struct {
	TargetInterface string
	Addresses       []string
	DNSServers      []string
}

type IPv6RuntimeCounter struct {
	RAAdvertisementCount uint64
	DHCPv6ReplyCount     uint64
	RAStatus             string
	RAStatusDetail       string
	DHCPv6Status         string
	DHCPv6StatusDetail   string
}
