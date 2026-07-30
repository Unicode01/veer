package app

import "github.com/Unicode01/veer/internal/netinfo"

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

	out := append([]HostNetworkInterface(nil), items...)
	for i := range out {
		out[i].Addresses = append([]HostInterfaceAddress(nil), out[i].Addresses...)
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

	out := append([]InterfaceInfo(nil), items...)
	for i := range out {
		out[i].Addrs = append([]string(nil), out[i].Addrs...)
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
