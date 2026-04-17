package app

import (
	"net"
	"net/netip"

	"forward/internal/netutil"
)

const (
	ipFamilyIPv4 = netutil.FamilyIPv4
	ipFamilyIPv6 = netutil.FamilyIPv6
)

type ipLiteralPairInfo struct {
	firstFamily  string
	secondFamily string
}

func normalizeIPLiteral(value string) (string, error) {
	return netutil.NormalizeIPLiteral(value)
}

func parseIPLiteral(value string) net.IP {
	return netutil.ParseIPLiteral(value)
}

func parseIPLiteralAddr(value string) (netip.Addr, bool) {
	return netutil.ParseIPLiteralAddr(value)
}

func canonicalIPLiteral(ip net.IP) string {
	return netutil.CanonicalIPLiteral(ip)
}

func ipLiteralFamilyFromAddr(addr netip.Addr) string {
	return netutil.IPLiteralFamilyFromAddr(addr)
}

func ipLiteralFamily(value string) string {
	return netutil.IPLiteralFamily(value)
}

func ipLiteralIsWildcard(value string) bool {
	return netutil.IPLiteralIsWildcard(value)
}

func analyzeIPLiteralPair(a, b string) ipLiteralPairInfo {
	info := netutil.AnalyzeIPLiteralPair(a, b)
	return ipLiteralPairInfo{
		firstFamily:  info.FirstFamily,
		secondFamily: info.SecondFamily,
	}
}

func (info ipLiteralPairInfo) mixedFamily() bool {
	return info.firstFamily != "" && info.secondFamily != "" && info.firstFamily != info.secondFamily
}

func (info ipLiteralPairInfo) usesIPv6() bool {
	return info.firstFamily == ipFamilyIPv6 || info.secondFamily == ipFamilyIPv6
}

func ipLiteralPairIsPureIPv4(a, b string) bool {
	return netutil.IPLiteralPairIsPureIPv4(a, b)
}

func isVisibleInterfaceIP(ip net.IP) bool {
	return netutil.IsVisibleInterfaceIP(ip)
}

func tcpListenNetworkForIP(bindIP string) string {
	return netutil.TCPListenNetworkForIP(bindIP)
}

func tcpListenNetworkForAddr(addr string) string {
	return netutil.TCPListenNetworkForAddr(addr)
}

func udpListenNetworkForIP(bindIP string) string {
	return netutil.UDPListenNetworkForIP(bindIP)
}

func udpNetworkForIP(ip net.IP) string {
	return netutil.UDPNetworkForIP(ip)
}

func ipv4BytesToUint32(ip net.IP) uint32 {
	return netutil.IPv4BytesToUint32(ip)
}

func kernelFamilyLabel(family string) string {
	return netutil.KernelFamilyLabel(family)
}

func normalizeKernelFamilyIP(ip net.IP, family string) net.IP {
	return netutil.NormalizeKernelFamilyIP(ip, family)
}

func zeroKernelFamilyIP(family string) net.IP {
	return netutil.ZeroKernelFamilyIP(family)
}

func parseKernelExplicitIP(text string, family string) (net.IP, error) {
	return netutil.ParseKernelExplicitIP(text, family)
}

func parseKernelInboundIP(text string, family string) (net.IP, bool, error) {
	return netutil.ParseKernelInboundIP(text, family)
}

func splitKernelUsableSourceIPs(addrs []net.IP, family string) ([]net.IP, []net.IP) {
	return netutil.SplitKernelUsableSourceIPs(addrs, family)
}

func selectKernelAutoSourceIP(ifaceName string, family string, usable []net.IP, linkLocal []net.IP) (net.IP, error) {
	return netutil.SelectKernelAutoSourceIP(ifaceName, family, usable, linkLocal)
}

const (
	kernelDefaultNATPortMin     = netutil.KernelDefaultNATPortMin
	kernelDefaultNATPortMax     = netutil.KernelDefaultNATPortMax
	kernelMinimumAllowedNATPort = netutil.KernelMinimumAllowedNATPort
	kernelMaximumAllowedNATPort = netutil.KernelMaximumAllowedNATPort
)

func normalizeKernelNATPortRange(portMin int, portMax int) (int, int, error) {
	return netutil.NormalizeKernelNATPortRange(portMin, portMax)
}

func effectiveKernelNATPortRange(portMin int, portMax int) (int, int) {
	return netutil.EffectiveKernelNATPortRange(portMin, portMax)
}
