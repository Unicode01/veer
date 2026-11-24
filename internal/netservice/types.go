package netservice

import "time"

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
	// PrefixLifetimes holds, by prefix as written in Prefixes, when the
	// delegation a prefix comes from stops being preferred and valid. The
	// lifetimes advertised for it never reach past those times. A prefix
	// with no entry, or a zero time, has only the advertiser's own limits.
	PrefixLifetimes map[string]RAPrefixLifetime
}

// RAPrefixLifetime is when an advertised prefix stops being preferred and
// valid; a zero time means no such limit.
type RAPrefixLifetime struct {
	PreferredUntil time.Time
	ValidUntil     time.Time
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
