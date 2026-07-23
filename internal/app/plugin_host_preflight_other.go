//go:build !linux

package app

func pluginRawL2FeatureStatus() PluginHostFeatureStatus {
	return PluginHostFeatureStatus{Reason: "raw L2 sockets require Linux"}
}

func pluginNetOffloadFeatureStatus() PluginHostFeatureStatus {
	return PluginHostFeatureStatus{Reason: "network offload control requires Linux and ethtool"}
}

func pluginNetworkNamespaceFeatureStatus() PluginHostFeatureStatus {
	return PluginHostFeatureStatus{Reason: "network namespaces require Linux"}
}

func pluginTunTapFeatureStatus() PluginHostFeatureStatus {
	return PluginHostFeatureStatus{Reason: "TUN/TAP devices require Linux"}
}
