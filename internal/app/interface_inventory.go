package app

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
