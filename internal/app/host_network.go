package app

import "forward/internal/netinfo"

var loadHostNetworkInterfacesForTests func() ([]HostNetworkInterface, error)

func loadCurrentHostNetworkInterfaces() ([]HostNetworkInterface, error) {
	load := loadHostNetworkInterfaces
	if loadHostNetworkInterfacesForTests != nil {
		load = loadHostNetworkInterfacesForTests
	}
	return load()
}

func loadHostNetworkInterfaces() ([]HostNetworkInterface, error) {
	items, err := netinfo.LoadHostNetworkInterfaces()
	if err != nil {
		return nil, err
	}

	out := make([]HostNetworkInterface, 0, len(items))
	for _, item := range items {
		addresses := make([]HostInterfaceAddress, 0, len(item.Addresses))
		for _, addr := range item.Addresses {
			addresses = append(addresses, HostInterfaceAddress{
				Family:    addr.Family,
				IP:        addr.IP,
				CIDR:      addr.CIDR,
				PrefixLen: addr.PrefixLen,
			})
		}
		out = append(out, HostNetworkInterface{
			Name:             item.Name,
			Kind:             item.Kind,
			Parent:           item.Parent,
			DefaultIPv4Route: item.DefaultIPv4Route,
			DefaultIPv6Route: item.DefaultIPv6Route,
			Addresses:        addresses,
		})
	}
	return out, nil
}

func buildHostNetworkInterfaceMap(items []HostNetworkInterface) map[string]HostNetworkInterface {
	if len(items) == 0 {
		return map[string]HostNetworkInterface{}
	}
	out := make(map[string]HostNetworkInterface, len(items))
	for _, item := range items {
		out[item.Name] = item
	}
	return out
}

func loadInterfaceInfos() ([]InterfaceInfo, error) {
	items, err := netinfo.LoadInterfaceInfos()
	if err != nil {
		return nil, err
	}

	out := make([]InterfaceInfo, 0, len(items))
	for _, item := range items {
		out = append(out, InterfaceInfo{
			Name:   item.Name,
			Addrs:  append([]string(nil), item.Addrs...),
			Parent: item.Parent,
			Kind:   item.Kind,
		})
	}
	return out, nil
}

func buildInterfaceInfoMap(items []InterfaceInfo) map[string]InterfaceInfo {
	if len(items) == 0 {
		return map[string]InterfaceInfo{}
	}
	out := make(map[string]InterfaceInfo, len(items))
	for _, item := range items {
		out[item.Name] = item
	}
	return out
}
