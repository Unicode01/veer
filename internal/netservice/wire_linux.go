//go:build linux

package netservice

import "net"

const (
	DHCPv4ClientPort           = dhcpv4ClientPort
	DHCPv4ServerPort           = dhcpv4ServerPort
	DHCPv4BootReply            = dhcpv4BootReply
	DHCPv4HardwareTypeEthernet = dhcpv4HWTypeEthernet
	DHCPv4MagicCookie          = dhcpv4MagicCookie
	DHCPv4OptionRequestedIP    = dhcpv4OptionRequestedIP
	DHCPv4OptionMessageType    = dhcpv4OptionMessageType
	DHCPv4OptionServerID       = dhcpv4OptionServerID
	DHCPv4OptionClientID       = dhcpv4OptionClientID
	DHCPv4OptionEnd            = dhcpv4OptionEnd
	DHCPv4MessageDiscover      = dhcpv4MessageDiscover
	DHCPv4MessageOffer         = dhcpv4MessageOffer
	DHCPv4MessageRequest       = dhcpv4MessageRequest
	DHCPv4MessageAck           = dhcpv4MessageAck
	DHCPv4MessageNak           = dhcpv4MessageNak
	DHCPv4MinMessageSize       = dhcpv4MinMessageSize
	IPv4ProtocolUDP            = ipv4ProtocolUDP

	DHCPv6ClientPort       = dhcpv6ClientPort
	DHCPv6ServerPort       = dhcpv6ServerPort
	DHCPv6MessageSolicit   = dhcpv6MessageSolicit
	DHCPv6MessageAdvertise = dhcpv6MessageAdvertise
	DHCPv6MessageRequest   = dhcpv6MessageRequest
	DHCPv6MessageReply     = dhcpv6MessageReply
	DHCPv6OptionClientID   = dhcpv6OptionClientID
	DHCPv6OptionServerID   = dhcpv6OptionServerID
	DHCPv6OptionIANA       = dhcpv6OptionIANA
	DHCPv6OptionIAAddr     = dhcpv6OptionIAAddr

	IPv6RAHopLimit = ipv6RAHopLimit
)

type DHCPv4Frame = managedNetworkDHCPv4Frame
type DHCPv4Message = parsedManagedNetworkDHCPv4Message
type DHCPv6Message = parsedDHCPv6Message

func ParseDHCPv4Message(packet []byte) (DHCPv4Message, error) {
	return parseManagedNetworkDHCPv4Message(packet)
}

func BuildDHCPv4Option(code byte, value []byte) []byte {
	return buildManagedNetworkDHCPv4Option(code, value)
}

func ParseDHCPv6Message(packet []byte) (DHCPv6Message, error) {
	return parseDHCPv6Message(packet)
}

func BuildDHCPv6Option(code uint16, value []byte) ([]byte, error) {
	return appendDHCPv6Option(nil, code, value, 4+len(value))
}

func BuildDHCPv6DUID(mac net.HardwareAddr) []byte {
	return buildDHCPv6DUID(mac)
}

func DHCPv6AllServersAndRelays() net.IP {
	return append(net.IP(nil), dhcpv6AllServersAndRelays...)
}

func BuildIPv6SourceLLAOption(mac net.HardwareAddr) []byte {
	return buildIPv6SourceLLAOption(mac)
}

func Htons(value uint16) uint16 {
	return htonsUnix(value)
}
