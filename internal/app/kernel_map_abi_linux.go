//go:build linux

package app

import (
	"encoding/binary"
	"fmt"

	"github.com/cilium/ebpf"
)

type kernelMapABIContract struct {
	name  string
	key   interface{}
	value interface{}
}

func validateKernelMapABIContracts(spec *ebpf.CollectionSpec, objectLabel string, contracts []kernelMapABIContract) error {
	return validateKernelMapABIContractsWithPresence(spec, objectLabel, contracts, true)
}

func validatePresentKernelMapABIContracts(spec *ebpf.CollectionSpec, objectLabel string, contracts []kernelMapABIContract) error {
	return validateKernelMapABIContractsWithPresence(spec, objectLabel, contracts, false)
}

func validateKernelMapABIContractsWithPresence(spec *ebpf.CollectionSpec, objectLabel string, contracts []kernelMapABIContract, requireAll bool) error {
	if spec == nil {
		return fmt.Errorf("embedded %s eBPF object is missing", objectLabel)
	}
	for _, contract := range contracts {
		mapSpec := spec.Maps[contract.name]
		if mapSpec == nil {
			if requireAll {
				return fmt.Errorf("embedded %s eBPF object is missing map %q", objectLabel, contract.name)
			}
			continue
		}
		keySize := binary.Size(contract.key)
		valueSize := binary.Size(contract.value)
		if keySize < 0 || valueSize < 0 {
			return fmt.Errorf("embedded %s eBPF object map %q has an unsupported Go ABI contract", objectLabel, contract.name)
		}
		if mapSpec.KeySize != uint32(keySize) || mapSpec.ValueSize != uint32(valueSize) {
			return fmt.Errorf(
				"embedded %s eBPF object map %q ABI mismatch: key_size=%d value_size=%d, Go encoding expects key_size=%d value_size=%d; rebuild eBPF objects before compiling",
				objectLabel,
				contract.name,
				mapSpec.KeySize,
				mapSpec.ValueSize,
				keySize,
				valueSize,
			)
		}
	}
	return nil
}

func tcKernelMapABIContracts() []kernelMapABIContract {
	return []kernelMapABIContract{
		{name: kernelRulesMapNameV4, key: tcRuleKeyV4{}, value: tcRuleValueV4{}},
		{name: kernelRulesMapNameV6, key: tcRuleKeyV6{}, value: tcRuleValueV6{}},
		{name: kernelFlowsMapNameV4, key: tcFlowKeyV4{}, value: tcFlowValueV4{}},
		{name: kernelTCFlowsOldMapNameV4, key: tcFlowKeyV4{}, value: tcFlowValueV4{}},
		{name: "scratch_flow_v4", key: uint32(0), value: tcFlowValueV4{}},
		{name: "scratch_flow_aux_v4", key: uint32(0), value: tcFlowValueV4{}},
		{name: "scratch_flow_key_v4", key: uint32(0), value: tcFlowKeyV4{}},
		{name: kernelFlowsMapNameV6, key: tcFlowKeyV6{}, value: tcFlowValueV6{}},
		{name: kernelTCFlowsOldMapNameV6, key: tcFlowKeyV6{}, value: tcFlowValueV6{}},
		{name: "scratch_flow_v6", key: uint32(0), value: tcFlowValueV6{}},
		{name: "scratch_flow_aux_v6", key: uint32(0), value: tcFlowValueV6{}},
		{name: "scratch_flow_key_v6", key: uint32(0), value: tcFlowKeyV6{}},
		{name: kernelNatPortsMapNameV4, key: tcNATPortKeyV4{}, value: tcNATPortValue{}},
		{name: kernelTCNatPortsOldMapNameV4, key: tcNATPortKeyV4{}, value: tcNATPortValue{}},
		{name: kernelNatPortsMapNameV6, key: tcNATPortKeyV6{}, value: tcNATPortValue{}},
		{name: kernelTCNatPortsOldMapNameV6, key: tcNATPortKeyV6{}, value: tcNATPortValue{}},
		{name: kernelIfParentMapName, key: uint32(0), value: uint32(0)},
		{name: kernelLocalIPv4MapName, key: uint32(0), value: uint8(0)},
		{name: kernelLocalMACMapName, key: uint32(0), value: kernelLocalMACValue{}},
		{name: kernelNATConfigMapName, key: uint32(0), value: tcNATConfigValueV4{}},
		{name: kernelStatsMapName, key: uint32(0), value: kernelStatsValueV4{}},
		{name: kernelDiagMapName, key: uint32(0), value: kernelDiagValueV4{}},
		{name: kernelOccupancyMapName, key: uint32(0), value: kernelOccupancyValueV4{}},
		{name: kernelTCFlowMigrationStateMapName, key: uint32(0), value: uint32(0)},
		{name: kernelTCProgramChainMapName, key: uint32(0), value: uint32(0)},
		{name: kernelTCPluginConfigMapName, key: uint32(0), value: kernelTCPluginConfigV4{}},
		{name: kernelTCPluginInterfacesMapName, key: kernelTCPluginInterfaceKeyV4{}, value: kernelTCPluginInterfaceValueV4{}},
		{name: kernelTCPluginMetricsMapName, key: uint32(0), value: kernelTCPluginMetricValue{}},
		{name: kernelTCPacketMetadataGenerationMapNameV4, key: uint32(0), value: uint64(0)},
		{name: kernelTCPacketMetadataGenerationMapNameV6, key: uint32(0), value: uint64(0)},
	}
}

func xdpKernelMapABIContracts() []kernelMapABIContract {
	return []kernelMapABIContract{
		{name: kernelRulesMapNameV4, key: tcRuleKeyV4{}, value: xdpRuleValueV4{}},
		{name: kernelRulesMapNameV6, key: tcRuleKeyV6{}, value: xdpRuleValueV6{}},
		{name: kernelFlowsMapNameV4, key: tcFlowKeyV4{}, value: xdpFlowValueV4{}},
		{name: kernelXDPFlowsOldMapNameV4, key: tcFlowKeyV4{}, value: xdpFlowValueV4{}},
		{name: kernelXDPFlowScratchV4MapName, key: uint32(0), value: xdpFlowValueV4{}},
		{name: kernelXDPFlowAuxScratchV4MapName, key: uint32(0), value: xdpFlowValueV4{}},
		{name: kernelFlowsMapNameV6, key: tcFlowKeyV6{}, value: tcFlowValueV6{}},
		{name: kernelXDPFlowsOldMapNameV6, key: tcFlowKeyV6{}, value: tcFlowValueV6{}},
		{name: kernelXDPFlowScratchV6MapName, key: uint32(0), value: tcFlowValueV6{}},
		{name: kernelXDPFlowAuxScratchV6MapName, key: uint32(0), value: tcFlowValueV6{}},
		{name: "xdp_flow_key_scratch_v6", key: uint32(0), value: tcFlowKeyV6{}},
		{name: "xdp_flow_aux_key_scratch_v6", key: uint32(0), value: tcFlowKeyV6{}},
		{name: "xdp_rule_key_scratch_v6", key: uint32(0), value: tcRuleKeyV6{}},
		{name: kernelNatPortsMapNameV4, key: tcNATPortKeyV4{}, value: tcNATPortValue{}},
		{name: kernelTCNatPortsOldMapNameV4, key: tcNATPortKeyV4{}, value: tcNATPortValue{}},
		{name: kernelNatPortsMapNameV6, key: tcNATPortKeyV6{}, value: tcNATPortValue{}},
		{name: kernelTCNatPortsOldMapNameV6, key: tcNATPortKeyV6{}, value: tcNATPortValue{}},
		{name: kernelLocalIPv4MapName, key: uint32(0), value: uint8(0)},
		{name: kernelLocalMACMapName, key: uint32(0), value: kernelLocalMACValue{}},
		{name: kernelNATConfigMapName, key: uint32(0), value: tcNATConfigValueV4{}},
		{name: kernelStatsMapName, key: uint32(0), value: kernelStatsValueV4{}},
		{name: kernelDiagMapName, key: uint32(0), value: kernelDiagValueV4{}},
		{name: kernelOccupancyMapName, key: uint32(0), value: kernelOccupancyValueV4{}},
		{name: kernelXDPFlowMigrationStateMapName, key: uint32(0), value: uint32(0)},
		{name: kernelXDPRedirectMapName, key: uint32(0), value: uint32(0)},
		{name: kernelXDPProgramChainMapName, key: uint32(0), value: uint32(0)},
	}
}
