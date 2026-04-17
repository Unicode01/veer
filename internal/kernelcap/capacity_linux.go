//go:build linux

package kernelcap

import (
	"fmt"

	"github.com/cilium/ebpf"
)

type MapCapacities struct {
	Rules    int
	Flows    int
	NATPorts int
}

type CountSnapshot struct {
	FlowsEntries int
	NATEntries   int
}

type MapNames struct {
	Rules           string
	Stats           string
	RulesV6         string
	Flows           string
	FlowsV6         string
	TCFlowsOldV4    string
	TCFlowsOldV6    string
	XDPFlowsOldV4   string
	XDPFlowsOldV6   string
	NATPorts        string
	NATPortsV6      string
	TCNATPortsOldV4 string
	TCNATPortsOldV6 string
}

const OldBankPlaceholderEntries = 1

func DesiredMapCapacitiesWithOccupancy(rulesConfiguredLimit int, flowsConfiguredLimit int, natConfiguredLimit int, requestedEntries int, counts CountSnapshot, includeNAT bool, adaptiveFlows bool, adaptiveNAT bool, profile AdaptiveMapProfile) MapCapacities {
	profile = normalizeAdaptiveMapProfile(profile)
	capacities := MapCapacities{
		Rules: EffectiveRulesMapLimit(rulesConfiguredLimit, requestedEntries),
		Flows: EffectiveFlowsMapLimit(flowsConfiguredLimit, requestedEntries, profile),
	}
	if adaptiveFlows {
		if liveDriven := AdaptiveMapLimitForLiveEntries(counts.FlowsEntries, profile.FlowsBaseLimit, FlowsMapAdaptiveMaxLimit); liveDriven > capacities.Flows {
			capacities.Flows = liveDriven
		}
	}
	if includeNAT {
		capacities.NATPorts = EffectiveNATMapLimit(natConfiguredLimit, requestedEntries, profile)
		if adaptiveNAT {
			if liveDriven := AdaptiveMapLimitForLiveEntries(counts.NATEntries, profile.NATBaseLimit, NATMapAdaptiveMaxLimit); liveDriven > capacities.NATPorts {
				capacities.NATPorts = liveDriven
			}
		}
	}
	return capacities
}

func ApplyMapCapacitiesWithOccupancy(spec *ebpf.CollectionSpec, rulesConfiguredLimit int, flowsConfiguredLimit int, natConfiguredLimit int, requestedEntries int, counts CountSnapshot, includeNAT bool, adaptiveFlows bool, adaptiveNAT bool, profile AdaptiveMapProfile, names MapNames) (MapCapacities, error) {
	if spec == nil {
		return MapCapacities{}, fmt.Errorf("kernel collection spec is missing")
	}

	capacities := DesiredMapCapacitiesWithOccupancy(rulesConfiguredLimit, flowsConfiguredLimit, natConfiguredLimit, requestedEntries, counts, includeNAT, adaptiveFlows, adaptiveNAT, profile)

	for _, name := range []string{names.Rules, names.Stats} {
		if err := SetCollectionMapCapacity(spec, name, capacities.Rules, true, "kernel rules"); err != nil {
			return MapCapacities{}, err
		}
	}
	if err := SetCollectionMapCapacity(spec, names.RulesV6, capacities.Rules, false, "kernel IPv6 rules"); err != nil {
		return MapCapacities{}, err
	}

	if err := SetCollectionMapCapacity(spec, names.Flows, capacities.Flows, true, "kernel flows"); err != nil {
		return MapCapacities{}, err
	}
	if err := SetCollectionMapCapacity(spec, names.FlowsV6, capacities.Flows, false, "kernel IPv6 flows"); err != nil {
		return MapCapacities{}, err
	}
	if err := SetCollectionMapCapacity(spec, names.TCFlowsOldV4, OldBankPlaceholderEntries, false, "tc old IPv4 flows"); err != nil {
		return MapCapacities{}, err
	}
	if err := SetCollectionMapCapacity(spec, names.TCFlowsOldV6, OldBankPlaceholderEntries, false, "tc old IPv6 flows"); err != nil {
		return MapCapacities{}, err
	}
	if err := SetCollectionMapCapacity(spec, names.XDPFlowsOldV4, OldBankPlaceholderEntries, false, "xdp old IPv4 flows"); err != nil {
		return MapCapacities{}, err
	}
	if err := SetCollectionMapCapacity(spec, names.XDPFlowsOldV6, OldBankPlaceholderEntries, false, "xdp old IPv6 flows"); err != nil {
		return MapCapacities{}, err
	}

	if includeNAT {
		if err := SetCollectionMapCapacity(spec, names.NATPorts, capacities.NATPorts, true, "kernel nat ports"); err != nil {
			return MapCapacities{}, err
		}
		if err := SetCollectionMapCapacity(spec, names.NATPortsV6, capacities.NATPorts, false, "kernel IPv6 nat ports"); err != nil {
			return MapCapacities{}, err
		}
		if err := SetCollectionMapCapacity(spec, names.TCNATPortsOldV4, OldBankPlaceholderEntries, false, "tc old IPv4 nat ports"); err != nil {
			return MapCapacities{}, err
		}
		if err := SetCollectionMapCapacity(spec, names.TCNATPortsOldV6, OldBankPlaceholderEntries, false, "tc old IPv6 nat ports"); err != nil {
			return MapCapacities{}, err
		}
	} else {
		if err := SetCollectionMapCapacity(spec, names.NATPorts, OldBankPlaceholderEntries, false, "kernel nat ports"); err != nil {
			return MapCapacities{}, err
		}
		if err := SetCollectionMapCapacity(spec, names.NATPortsV6, OldBankPlaceholderEntries, false, "kernel IPv6 nat ports"); err != nil {
			return MapCapacities{}, err
		}
		if err := SetCollectionMapCapacity(spec, names.TCNATPortsOldV4, OldBankPlaceholderEntries, false, "tc old IPv4 nat ports"); err != nil {
			return MapCapacities{}, err
		}
		if err := SetCollectionMapCapacity(spec, names.TCNATPortsOldV6, OldBankPlaceholderEntries, false, "tc old IPv6 nat ports"); err != nil {
			return MapCapacities{}, err
		}
	}

	return capacities, nil
}

func SetCollectionMapCapacity(spec *ebpf.CollectionSpec, name string, capacity int, required bool, label string) error {
	if spec == nil {
		return fmt.Errorf("kernel collection spec is missing")
	}
	item := spec.Maps[name]
	if item == nil {
		if required {
			return fmt.Errorf("kernel collection spec is missing map %q", name)
		}
		return nil
	}
	if uint64(capacity) > uint64(^uint32(0)) {
		if label == "" {
			label = "kernel map"
		}
		return fmt.Errorf("%s capacity %d exceeds uint32 limit", label, capacity)
	}
	item.MaxEntries = uint32(capacity)
	return nil
}

func MapReusableWithCapacity(m *ebpf.Map, desiredLimit int) bool {
	if m == nil {
		return false
	}
	return int(m.MaxEntries()) >= desiredLimit
}
