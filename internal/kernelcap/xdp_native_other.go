//go:build !linux

package kernelcap

func DetectXDPNativeDevices() XDPNativeReport {
	return XDPNativeReport{Reason: "XDP requires Linux"}
}
