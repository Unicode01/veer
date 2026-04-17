package netinfo

type InterfaceInfo struct {
	Name   string
	Addrs  []string
	Parent string
	Kind   string
}

type HostInterfaceAddress struct {
	Family    string
	IP        string
	CIDR      string
	PrefixLen int
}

type HostNetworkInterface struct {
	Name             string
	Kind             string
	Parent           string
	DefaultIPv4Route bool
	DefaultIPv6Route bool
	Addresses        []HostInterfaceAddress
}
