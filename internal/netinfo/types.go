package netinfo

type InterfaceInfo struct {
	Name   string   `json:"name"`
	Addrs  []string `json:"addrs"`
	Parent string   `json:"parent,omitempty"`
	Kind   string   `json:"kind,omitempty"`
}

type HostInterfaceAddress struct {
	Family    string `json:"family"`
	IP        string `json:"ip"`
	CIDR      string `json:"cidr"`
	PrefixLen int    `json:"prefix_len"`
}

type HostNetworkInterface struct {
	Name             string                 `json:"name"`
	Kind             string                 `json:"kind,omitempty"`
	Parent           string                 `json:"parent,omitempty"`
	DefaultIPv4Route bool                   `json:"default_ipv4_route,omitempty"`
	DefaultIPv6Route bool                   `json:"default_ipv6_route,omitempty"`
	Addresses        []HostInterfaceAddress `json:"addresses,omitempty"`
}
