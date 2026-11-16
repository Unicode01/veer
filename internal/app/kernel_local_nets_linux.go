//go:build linux

package app

import (
	"errors"
	"fmt"
	"log"
	"net/netip"

	"github.com/cilium/ebpf"
)

// kernelLocalNetKeyV4 is struct local_net_key_v4, the key of an LPM trie:
// the prefix length, then the address in network byte order.
type kernelLocalNetKeyV4 struct {
	PrefixLen uint32
	Addr      [4]byte
}

// syncKernelEgressNATLocalMaps writes the egress NAT local inventory to the
// address and network maps of a program. Only the address map is required:
// without the network map egress NAT translates traffic for the host's other
// networks, as before it knew them, so a network map it cannot write is
// emptied and logged instead of failing the rules.
func syncKernelEgressNATLocalMaps(addrs *ebpf.Map, nets *ebpf.Map, inv kernelEgressNATLocalInventory) error {
	if err := syncKernelLocalIPv4Map(addrs, inv.Addrs); err != nil {
		return err
	}
	if nets == nil {
		return nil
	}
	if err := syncKernelLocalNetMap(nets, inv.Networks); err != nil {
		log.Printf("kernel dataplane: sync local network map failed, egress NAT translates traffic for local networks: %v", err)
		if clearErr := syncKernelLocalNetMap(nets, nil); clearErr != nil {
			log.Printf("kernel dataplane: clear local network map failed: %v", clearErr)
		}
	}
	return nil
}

// syncKernelLocalNetMap makes the map hold desired. Networks that keep the
// NAT go in before the networks routed around it and leave after them, so
// no step lets traffic for an uplink network out untranslated.
func syncKernelLocalNetMap(m *ebpf.Map, desired map[netip.Prefix]bool) error {
	if m == nil {
		return fmt.Errorf("kernel local network map is nil")
	}
	want := make(map[kernelLocalNetKeyV4]uint8, len(desired))
	for prefix, routed := range desired {
		if !prefix.Addr().Is4() {
			continue
		}
		key := kernelLocalNetKeyV4{PrefixLen: uint32(prefix.Bits()), Addr: prefix.Masked().Addr().As4()}
		var value uint8
		if routed {
			value = 1
		}
		want[key] = value
	}

	existing := make(map[kernelLocalNetKeyV4]uint8)
	iter := m.Iterate()
	var key kernelLocalNetKeyV4
	var value uint8
	for iter.Next(&key, &value) {
		existing[key] = value
	}
	if err := iter.Err(); err != nil {
		return fmt.Errorf("iterate kernel local network map: %w", err)
	}

	for _, pass := range []uint8{0, 1} {
		for key, value := range want {
			if value != pass {
				continue
			}
			if current, ok := existing[key]; ok && current == value {
				continue
			}
			if err := m.Put(key, value); err != nil {
				return fmt.Errorf("update local network %s: %w", formatKernelLocalNetKeyV4(key), err)
			}
		}
	}
	for _, pass := range []uint8{1, 0} {
		for key, value := range existing {
			if _, keep := want[key]; keep || value != pass {
				continue
			}
			if err := m.Delete(key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
				return fmt.Errorf("delete stale local network %s: %w", formatKernelLocalNetKeyV4(key), err)
			}
		}
	}
	return nil
}

func formatKernelLocalNetKeyV4(key kernelLocalNetKeyV4) string {
	return netip.PrefixFrom(netip.AddrFrom4(key.Addr), int(key.PrefixLen)).String()
}
