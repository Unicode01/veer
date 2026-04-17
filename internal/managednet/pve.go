package managednet

import (
	"sort"
	"strings"
)

func ParsePVEGuestNICs(vmid string, content string) []PVEGuestNIC {
	vmid = strings.TrimSpace(vmid)
	if vmid == "" {
		return nil
	}

	guestName := parsePVEGuestName(content)
	lines := strings.Split(content, "\n")
	out := make([]PVEGuestNIC, 0)
	for _, rawLine := range lines {
		line := strings.TrimSpace(strings.SplitN(rawLine, "#", 2)[0])
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(parts[0]))
		if !strings.HasPrefix(key, "net") {
			continue
		}
		slot := strings.TrimSpace(strings.TrimPrefix(key, "net"))
		if slot == "" {
			continue
		}
		out = append(out, PVEGuestNIC{
			VMID:       vmid,
			GuestName:  guestName,
			Slot:       slot,
			ConfigKey:  key,
			Bridge:     parsePVEBridgeFromConfigValue(parts[1]),
			MACAddress: parsePVENetworkMACAddress(parts[1]),
		})
	}
	if len(out) == 0 {
		return nil
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].VMID != out[j].VMID {
			return out[i].VMID < out[j].VMID
		}
		if out[i].ConfigKey != out[j].ConfigKey {
			return out[i].ConfigKey < out[j].ConfigKey
		}
		if out[i].Bridge != out[j].Bridge {
			return out[i].Bridge < out[j].Bridge
		}
		return out[i].MACAddress < out[j].MACAddress
	})
	return out
}

func parsePVEGuestName(content string) string {
	lines := strings.Split(content, "\n")
	hostname := ""
	for _, rawLine := range lines {
		line := strings.TrimSpace(strings.SplitN(rawLine, "#", 2)[0])
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(parts[0])) {
		case "name":
			return strings.TrimSpace(parts[1])
		case "hostname":
			if hostname == "" {
				hostname = strings.TrimSpace(parts[1])
			}
		}
	}
	return hostname
}

func parsePVENetworkMACAddress(value string) string {
	for _, token := range strings.Split(value, ",") {
		part := strings.TrimSpace(token)
		if part == "" {
			continue
		}
		kv := strings.SplitN(part, "=", 2)
		if len(kv) != 2 {
			continue
		}
		macAddress, err := normalizeManagedNetworkReservationMACAddress(kv[1])
		if err == nil {
			return macAddress
		}
	}
	return ""
}

func pveGuestNICLookupKey(vmid string, slot string) string {
	vmid = strings.TrimSpace(vmid)
	slot = strings.TrimSpace(slot)
	if vmid == "" || slot == "" {
		return ""
	}
	return vmid + "|" + slot
}

func indexPVEGuestNICs(items []PVEGuestNIC) map[string]PVEGuestNIC {
	if len(items) == 0 {
		return nil
	}
	out := make(map[string]PVEGuestNIC, len(items))
	for _, item := range items {
		key := pveGuestNICLookupKey(item.VMID, item.Slot)
		if key == "" {
			continue
		}
		out[key] = item
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func EnrichDiscoveredMACsWithPVEGuestNICs(items []DiscoveredMAC, nics []PVEGuestNIC) []DiscoveredMAC {
	if len(items) == 0 || len(nics) == 0 {
		return items
	}
	index := indexPVEGuestNICs(nics)
	if len(index) == 0 {
		return items
	}

	out := append([]DiscoveredMAC(nil), items...)
	for i := range out {
		vmid, slot, ok := parseProxmoxGuestPort(out[i].ChildInterface)
		if !ok {
			continue
		}
		nic, ok := index[pveGuestNICLookupKey(vmid, slot)]
		if !ok {
			continue
		}
		macAddress := strings.ToLower(strings.TrimSpace(out[i].MACAddress))
		if nic.MACAddress != "" && macAddress != "" && !strings.EqualFold(nic.MACAddress, macAddress) {
			continue
		}
		out[i].PVEVMID = nic.VMID
		out[i].PVEGuestName = nic.GuestName
		out[i].PVEGuestNIC = nic.ConfigKey
	}
	return out
}

func parseProxmoxGuestPort(name string) (string, string, bool) {
	name = strings.TrimSpace(name)
	if name == "" {
		return "", "", false
	}

	prefixLen := 0
	separator := byte(0)
	switch {
	case strings.HasPrefix(name, "tap"):
		prefixLen = 3
		separator = 'i'
	case strings.HasPrefix(name, "veth"):
		prefixLen = 4
		separator = 'i'
	case strings.HasPrefix(name, "fwpr"), strings.HasPrefix(name, "fwln"):
		prefixLen = 4
		if strings.HasPrefix(name, "fwpr") {
			separator = 'p'
		} else {
			separator = 'i'
		}
	default:
		return "", "", false
	}

	vmidStart := prefixLen
	vmidEnd := vmidStart
	for vmidEnd < len(name) && name[vmidEnd] >= '0' && name[vmidEnd] <= '9' {
		vmidEnd++
	}
	if vmidEnd == vmidStart || vmidEnd >= len(name) {
		return "", "", false
	}
	if name[vmidEnd] != separator {
		return "", "", false
	}
	slotStart := vmidEnd + 1
	if slotStart >= len(name) {
		return "", "", false
	}
	for idx := slotStart; idx < len(name); idx++ {
		if name[idx] < '0' || name[idx] > '9' {
			return "", "", false
		}
	}
	return name[vmidStart:vmidEnd], name[slotStart:], true
}
