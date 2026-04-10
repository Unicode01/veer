package app

import (
	"sort"
	"strings"
)

type managedNetworkPVEGuestNIC struct {
	VMID       string
	GuestName  string
	Slot       string
	ConfigKey  string
	Bridge     string
	MACAddress string
}

func parseManagedNetworkPVEGuestNICs(vmid string, content string) []managedNetworkPVEGuestNIC {
	vmid = strings.TrimSpace(vmid)
	if vmid == "" {
		return nil
	}

	guestName := parseManagedNetworkPVEGuestName(content)
	lines := strings.Split(content, "\n")
	out := make([]managedNetworkPVEGuestNIC, 0)
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
		out = append(out, managedNetworkPVEGuestNIC{
			VMID:       vmid,
			GuestName:  guestName,
			Slot:       slot,
			ConfigKey:  key,
			Bridge:     parseManagedNetworkPVEBridgeFromConfigValue(parts[1]),
			MACAddress: parseManagedNetworkPVENetworkMACAddress(parts[1]),
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

func parseManagedNetworkPVEGuestName(content string) string {
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

func parseManagedNetworkPVENetworkMACAddress(value string) string {
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

func managedNetworkPVEGuestNICLookupKey(vmid string, slot string) string {
	vmid = strings.TrimSpace(vmid)
	slot = strings.TrimSpace(slot)
	if vmid == "" || slot == "" {
		return ""
	}
	return vmid + "|" + slot
}

func indexManagedNetworkPVEGuestNICs(items []managedNetworkPVEGuestNIC) map[string]managedNetworkPVEGuestNIC {
	if len(items) == 0 {
		return nil
	}
	out := make(map[string]managedNetworkPVEGuestNIC, len(items))
	for _, item := range items {
		key := managedNetworkPVEGuestNICLookupKey(item.VMID, item.Slot)
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

func enrichManagedNetworkDiscoveredMACsWithPVEGuestNICs(items []managedNetworkDiscoveredMAC, nics []managedNetworkPVEGuestNIC) []managedNetworkDiscoveredMAC {
	if len(items) == 0 || len(nics) == 0 {
		return items
	}
	index := indexManagedNetworkPVEGuestNICs(nics)
	if len(index) == 0 {
		return items
	}

	out := append([]managedNetworkDiscoveredMAC(nil), items...)
	for i := range out {
		vmid, slot, ok := parseManagedNetworkProxmoxGuestPort(out[i].ChildInterface)
		if !ok {
			continue
		}
		nic, ok := index[managedNetworkPVEGuestNICLookupKey(vmid, slot)]
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
