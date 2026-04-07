//go:build linux

package app

import (
	"fmt"

	"github.com/cilium/ebpf"
)

func syncKernelNATConfigMap(m *ebpf.Map, portMin int, portMax int) error {
	if m == nil {
		return nil
	}

	portMin, portMax, err := normalizeKernelNATPortRange(portMin, portMax)
	if err != nil {
		return err
	}

	key := uint32(0)
	value := tcNATConfigValueV4{
		PortMin: uint32(portMin),
		PortMax: uint32(portMax),
	}
	if err := m.Put(key, value); err != nil {
		return fmt.Errorf("sync kernel nat config map: %w", err)
	}
	return nil
}

func syncKernelNATConfigMapForCollection(coll *ebpf.Collection, portMin int, portMax int) error {
	if coll == nil || coll.Maps == nil {
		return nil
	}
	return syncKernelNATConfigMap(coll.Maps[kernelNATConfigMapName], portMin, portMax)
}
