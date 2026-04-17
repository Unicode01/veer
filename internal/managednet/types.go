package managednet

import (
	"net"
	"strings"

	"github.com/vishvananda/netlink"
)

const (
	BridgeModeCreate                       = "create"
	BridgeModeExisting                     = "existing"
	ManagedNetworkHostInterfacesConfigPath = "/etc/network/interfaces"

	ReservationCandidateStatusAvailable   = "available"
	ReservationCandidateStatusReserved    = "reserved"
	ReservationCandidateStatusUnavailable = "unavailable"
	ReservationCandidateIPv4ChoicesLimit  = 5
)

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

type InterfaceInfo struct {
	Name   string
	Addrs  []string
	Parent string
	Kind   string
}

type ReservationCandidate struct {
	ManagedNetworkID          int64
	ManagedNetworkName        string
	ManagedNetworkBridge      string
	PVEVMID                   string
	PVEGuestName              string
	PVEGuestNIC               string
	ChildInterface            string
	MACAddress                string
	SuggestedIPv4             string
	IPv4Candidates            []string
	SuggestedRemark           string
	Status                    string
	StatusMessage             string
	ExistingReservationID     int64
	ExistingReservationIPv4   string
	ExistingReservationRemark string
}

type RepairResult struct {
	Bridges    []string
	GuestLinks []string
}

type PVEBridgeBinding struct {
	VMID   string
	Slot   string
	Bridge string
}

type PVEGuestNIC struct {
	VMID       string
	GuestName  string
	Slot       string
	ConfigKey  string
	Bridge     string
	MACAddress string
}

type DiscoveredMAC struct {
	ManagedNetworkID int64
	ChildInterface   string
	MACAddress       string
	ObservedIPv4s    []string
	PVEVMID          string
	PVEGuestName     string
	PVEGuestNIC      string
}

type PersistBridgeResult struct {
	Status         string `json:"status"`
	Bridge         string `json:"bridge"`
	InterfacesPath string `json:"interfaces_path,omitempty"`
	BackupPath     string `json:"backup_path,omitempty"`
	Message        string `json:"message,omitempty"`
}

type PersistBridgeIssue struct {
	Field   string
	Message string
}

type PersistedBridgeSpec struct {
	Name            string
	BridgeMTU       int
	BridgeVLANAware bool
	HardwareAddr    net.HardwareAddr
}

type RepairLinkOps interface {
	LinkByName(name string) (netlink.Link, error)
	LinkByIndex(index int) (netlink.Link, error)
	LinkSetNoMaster(link netlink.Link) error
	LinkSetMaster(link netlink.Link, master netlink.Link) error
	LinkSetUp(link netlink.Link) error
}

type RepairOptions struct {
	LoadPVEConfigs func() (map[string]string, error)
	LinkOps        RepairLinkOps
}

type CandidateDiscoveryOptions struct {
	LoadInterfaceInfos func() ([]InterfaceInfo, error)
	RepairOptions      RepairOptions
}

func (e PersistBridgeIssue) Error() string {
	return strings.TrimSpace(e.Message)
}

func normalizeManagedNetwork(item ManagedNetwork) ManagedNetwork {
	item.Name = strings.TrimSpace(item.Name)
	item.BridgeMode = normalizeManagedNetworkBridgeMode(item.BridgeMode)
	item.Bridge = strings.TrimSpace(item.Bridge)
	item.UplinkInterface = strings.TrimSpace(item.UplinkInterface)
	item.IPv4CIDR = strings.TrimSpace(item.IPv4CIDR)
	item.IPv4Gateway = strings.TrimSpace(item.IPv4Gateway)
	item.IPv4PoolStart = strings.TrimSpace(item.IPv4PoolStart)
	item.IPv4PoolEnd = strings.TrimSpace(item.IPv4PoolEnd)
	item.IPv4DNSServers = strings.TrimSpace(item.IPv4DNSServers)
	item.IPv6ParentInterface = strings.TrimSpace(item.IPv6ParentInterface)
	item.IPv6ParentPrefix = strings.TrimSpace(item.IPv6ParentPrefix)
	item.Remark = strings.TrimSpace(item.Remark)
	if item.BridgeMode == BridgeModeExisting {
		item.BridgeMTU = 0
		item.BridgeVLANAware = false
	}
	return item
}

func normalizeManagedNetworkBridgeMode(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", BridgeModeCreate:
		return BridgeModeCreate
	case BridgeModeExisting:
		return BridgeModeExisting
	default:
		return strings.ToLower(strings.TrimSpace(value))
	}
}
