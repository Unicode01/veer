package store

type Rule struct {
	ID               int64
	InInterface      string
	InIP             string
	InPort           int
	OutInterface     string
	OutIP            string
	OutSourceIP      string
	OutPort          int
	Protocol         string
	Remark           string
	Tag              string
	Enabled          bool
	Transparent      bool
	EnginePreference string
}

type Site struct {
	ID              int64
	Domain          string
	ListenIP        string
	ListenIface     string
	BackendIP       string
	BackendSourceIP string
	BackendHTTP     int
	BackendHTTPS    int
	Tag             string
	Enabled         bool
	Transparent     bool
}

type PortRange struct {
	ID           int64
	InInterface  string
	InIP         string
	StartPort    int
	EndPort      int
	OutInterface string
	OutIP        string
	OutSourceIP  string
	OutStartPort int
	Protocol     string
	Remark       string
	Tag          string
	Enabled      bool
	Transparent  bool
}

type EgressNAT struct {
	ID              int64
	ParentInterface string
	ChildInterface  string
	OutInterface    string
	OutSourceIP     string
	Protocol        string
	NATType         string
	Enabled         bool
}

type IPv6Assignment struct {
	ID              int64
	ParentInterface string
	TargetInterface string
	ParentPrefix    string
	AssignedPrefix  string
	Address         string
	PrefixLen       int
	Remark          string
	Enabled         bool
}

type ManagedNetwork struct {
	ID                  int64
	Name                string
	BridgeMode          string
	Bridge              string
	BridgeMTU           int
	BridgeVLANAware     bool
	UplinkInterface     string
	IPv4Enabled         bool
	IPv4CIDR            string
	IPv4Gateway         string
	IPv4PoolStart       string
	IPv4PoolEnd         string
	IPv4DNSServers      string
	IPv6Enabled         bool
	IPv6ParentInterface string
	IPv6ParentPrefix    string
	IPv6AssignmentMode  string
	AutoEgressNAT       bool
	Remark              string
	Enabled             bool
}

type ManagedNetworkReservation struct {
	ID               int64
	ManagedNetworkID int64
	MACAddress       string
	IPv4Address      string
	Remark           string
}

type RuleFilter struct {
	IDs          map[int64]struct{}
	Tags         map[string]struct{}
	Protocols    map[string]struct{}
	Statuses     map[string]struct{}
	Enabled      *bool
	Transparent  *bool
	InInterface  string
	OutInterface string
	InIP         string
	OutIP        string
	OutSourceIP  string
	InPort       int
	OutPort      int
	Query        string
}
