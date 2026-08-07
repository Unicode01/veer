//go:build linux

package app

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"strings"
)

const (
	kernelRulesMapNameV4    = "rules_v4"
	kernelFlowsMapNameV4    = "flows_v4"
	kernelNatPortsMapNameV4 = "nat_ports_v4"
	kernelRulesMapNameV6    = "rules_v6"
	kernelFlowsMapNameV6    = "flows_v6"
	kernelNatPortsMapNameV6 = "nat_ports_v6"
)

const kernelRuleFlowContractFlags = kernelRuleFlagFullNAT | kernelRuleFlagEgressNAT | kernelRuleFlagPassthrough | kernelRuleFlagFullCone

type kernelRuleFlowContractV4 struct {
	Key         tcRuleKeyV4
	BackendAddr uint32
	BackendPort uint16
	Flags       uint16
	OutIfIndex  uint32
	NATAddr     uint32
}

type kernelRuleFlowContractV6 struct {
	Key         tcRuleKeyV6
	BackendAddr [16]byte
	BackendPort uint16
	Flags       uint16
	OutIfIndex  uint32
	NATAddr     [16]byte
}

type tcRuleKeyV6 struct {
	IfIndex uint32
	DstAddr [16]byte
	DstPort uint16
	Proto   uint8
	Pad     uint8
}

type tcRuleValueV6 struct {
	RuleID      uint32
	BackendAddr [16]byte
	BackendPort uint16
	Flags       uint16
	OutIfIndex  uint32
	NATAddr     [16]byte
	SrcMAC      [6]byte
	DstMAC      [6]byte
	Revision    uint64
}

type tcFlowKeyV6 struct {
	IfIndex uint32
	SrcAddr [16]byte
	DstAddr [16]byte
	SrcPort uint16
	DstPort uint16
	Proto   uint8
	Pad     [3]uint8
}

type tcFlowValueV6 struct {
	RuleID           uint32
	FrontAddr        [16]byte
	ClientAddr       [16]byte
	NATAddr          [16]byte
	InIfIndex        uint32
	FrontPort        uint16
	ClientPort       uint16
	NATPort          uint16
	Flags            uint16
	FrontMAC         [6]byte
	ClientMAC        [6]byte
	Pad              uint32
	LastSeenNS       uint64
	FrontCloseSeenNS uint64
	RuleRevision     uint64
	SessionID        uint64
}

type tcNATPortKeyV6 struct {
	IfIndex uint32
	NATAddr [16]byte
	NATPort uint16
	Proto   uint8
	Pad     uint8
}

func normalizedKernelPreparedRuleFamily(family string) string {
	if family == ipFamilyIPv6 {
		return ipFamilyIPv6
	}
	return ipFamilyIPv4
}

func normalizedKernelPreparedRuleSpec(spec kernelPreparedRuleSpec) kernelPreparedRuleSpec {
	spec.Family = normalizedKernelPreparedRuleFamily(spec.Family)
	return spec
}

func sameKernelPreparedRuleSpec(a, b kernelPreparedRuleSpec) bool {
	return normalizedKernelPreparedRuleSpec(a) == normalizedKernelPreparedRuleSpec(b)
}

func kernelPreparedRuleFamily(item preparedKernelRule) string {
	if item.spec.Family == "" {
		if family := ipLiteralFamily(item.rule.InIP); family != "" {
			return normalizedKernelPreparedRuleFamily(family)
		}
		if family := ipLiteralFamily(item.rule.OutIP); family != "" {
			return normalizedKernelPreparedRuleFamily(family)
		}
	}
	return normalizedKernelPreparedRuleFamily(item.spec.Family)
}

func kernelPreparedRuleMapNames(family string) (rules string, flows string, nat string, err error) {
	switch strings.TrimSpace(family) {
	case "", ipFamilyIPv4:
		return kernelRulesMapNameV4, kernelFlowsMapNameV4, kernelNatPortsMapNameV4, nil
	case ipFamilyIPv6:
		return kernelRulesMapNameV6, kernelFlowsMapNameV6, kernelNatPortsMapNameV6, nil
	default:
		return "", "", "", fmt.Errorf("unsupported kernel rule family %q", family)
	}
}

func encodePreparedKernelRuleV4(item preparedKernelRule) (tcRuleKeyV4, tcRuleValueV4, error) {
	if kernelPreparedRuleFamily(item) != ipFamilyIPv4 {
		return tcRuleKeyV4{}, tcRuleValueV4{}, fmt.Errorf("prepared kernel rule family %q is not encodable as IPv4", item.spec.Family)
	}
	return item.key, item.value, nil
}

func encodePreparedKernelRuleV6(item preparedKernelRule) (tcRuleKeyV6, tcRuleValueV6, error) {
	if kernelPreparedRuleFamily(item) != ipFamilyIPv6 {
		return tcRuleKeyV6{}, tcRuleValueV6{}, fmt.Errorf("prepared kernel rule family %q is not encodable as IPv6", item.spec.Family)
	}
	if item.rule.ID <= 0 || item.rule.ID > int64(^uint32(0)) {
		return tcRuleKeyV6{}, tcRuleValueV6{}, fmt.Errorf("kernel dataplane requires a rule id in uint32 range")
	}

	outIfIndex := item.value.OutIfIndex
	if outIfIndex == 0 && item.outIfIndex > 0 {
		outIfIndex = uint32(item.outIfIndex)
	}

	return tcRuleKeyV6{
			IfIndex: uint32(item.inIfIndex),
			DstAddr: item.spec.DstAddr,
			DstPort: uint16(item.rule.InPort),
			Proto:   kernelRuleProtocol(item.rule.Protocol),
		}, tcRuleValueV6{
			RuleID:      uint32(item.rule.ID),
			BackendAddr: item.spec.BackendAddr,
			BackendPort: uint16(item.rule.OutPort),
			Flags:       item.value.Flags,
			OutIfIndex:  outIfIndex,
			NATAddr:     item.spec.NATAddr,
			SrcMAC:      item.value.SrcMAC,
			DstMAC:      item.value.DstMAC,
			Revision:    item.value.Revision,
		}, nil
}

func kernelRuleFlowRevisionV4(key tcRuleKeyV4, backendAddr uint32, backendPort uint16, flags uint16, outIfIndex uint32, natAddr uint32) (uint64, error) {
	return hashKernelRuleFlowContract(kernelRuleFlowContractV4{
		Key:         key,
		BackendAddr: backendAddr,
		BackendPort: backendPort,
		Flags:       flags & kernelRuleFlowContractFlags,
		OutIfIndex:  outIfIndex,
		NATAddr:     natAddr,
	})
}

func kernelRuleFlowRevisionV6(key tcRuleKeyV6, backendAddr [16]byte, backendPort uint16, flags uint16, outIfIndex uint32, natAddr [16]byte) (uint64, error) {
	return hashKernelRuleFlowContract(kernelRuleFlowContractV6{
		Key:         key,
		BackendAddr: backendAddr,
		BackendPort: backendPort,
		Flags:       flags & kernelRuleFlowContractFlags,
		OutIfIndex:  outIfIndex,
		NATAddr:     natAddr,
	})
}

func hashKernelRuleFlowContract(value any) (uint64, error) {
	var payload bytes.Buffer
	if err := binary.Write(&payload, binary.LittleEndian, value); err != nil {
		return 0, fmt.Errorf("encode kernel flow contract: %w", err)
	}
	sum := sha256.Sum256(payload.Bytes())
	revision := binary.LittleEndian.Uint64(sum[:8])
	if revision == 0 {
		revision = 1
	}
	return revision, nil
}

func assignPreparedKernelRuleRevision(item *preparedKernelRule) error {
	if item == nil {
		return nil
	}
	switch kernelPreparedRuleFamily(*item) {
	case ipFamilyIPv6:
		key, value, err := encodePreparedKernelRuleV6(*item)
		if err != nil {
			return err
		}
		revision, err := kernelRuleFlowRevisionV6(key, value.BackendAddr, value.BackendPort, value.Flags, value.OutIfIndex, value.NATAddr)
		if err != nil {
			return err
		}
		item.value.Revision = revision
	default:
		revision, err := kernelRuleFlowRevisionV4(item.key, item.value.BackendAddr, item.value.BackendPort, item.value.Flags, item.value.OutIfIndex, item.value.NATAddr)
		if err != nil {
			return err
		}
		item.value.Revision = revision
	}
	return nil
}

func preparedKernelRuleFlowRevision(item preparedKernelRule) (uint64, error) {
	if item.value.Revision != 0 {
		return item.value.Revision, nil
	}
	if err := assignPreparedKernelRuleRevision(&item); err != nil {
		return 0, err
	}
	return item.value.Revision, nil
}

func kernelRuleFlowContractFlagsFromXDP(flags uint16) uint16 {
	var normalized uint16
	if flags&xdpRuleFlagFullNAT != 0 {
		normalized |= kernelRuleFlagFullNAT
	}
	if flags&xdpRuleFlagEgressNAT != 0 {
		normalized |= kernelRuleFlagEgressNAT
	}
	if flags&xdpRuleFlagFullCone != 0 {
		normalized |= kernelRuleFlagFullCone
	}
	return normalized
}

func assignPreparedXDPKernelRuleRevision(item *preparedXDPKernelRule) error {
	if item == nil {
		return nil
	}
	switch xdpPreparedRuleFamily(*item) {
	case ipFamilyIPv6:
		revision, err := kernelRuleFlowRevisionV6(item.keyV6, item.valueV6.BackendAddr, item.valueV6.BackendPort, kernelRuleFlowContractFlagsFromXDP(item.valueV6.Flags), item.valueV6.OutIfIndex, item.valueV6.NATAddr)
		if err != nil {
			return err
		}
		item.valueV6.Revision = revision
	default:
		revision, err := kernelRuleFlowRevisionV4(item.keyV4, item.valueV4.BackendAddr, item.valueV4.BackendPort, kernelRuleFlowContractFlagsFromXDP(item.valueV4.Flags), item.valueV4.OutIfIndex, item.valueV4.NATAddr)
		if err != nil {
			return err
		}
		item.valueV4.Revision = revision
	}
	return nil
}

func preparedXDPKernelRuleFlowRevision(item preparedXDPKernelRule) (uint64, error) {
	if xdpPreparedRuleFamily(item) == ipFamilyIPv6 && item.valueV6.Revision != 0 {
		return item.valueV6.Revision, nil
	}
	if xdpPreparedRuleFamily(item) == ipFamilyIPv4 && item.valueV4.Revision != 0 {
		return item.valueV4.Revision, nil
	}
	if err := assignPreparedXDPKernelRuleRevision(&item); err != nil {
		return 0, err
	}
	if xdpPreparedRuleFamily(item) == ipFamilyIPv6 {
		return item.valueV6.Revision, nil
	}
	return item.valueV4.Revision, nil
}

func compareKernelPreparedAddr(a, b kernelPreparedAddr) int {
	return bytes.Compare(a[:], b[:])
}
