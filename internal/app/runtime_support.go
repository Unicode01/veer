package app

import (
	"net"
	"os/exec"
	"syscall"

	"forward/internal/ipcsec"
	"forward/internal/managednet"
	"forward/internal/procrun"
	"forward/internal/socketio"
	"forward/internal/tproxysetup"
)

type udpReplyInfo = socketio.ReplyInfo

const (
	controlSocketDirName  = ipcsec.ControlSocketDirName
	controlSocketFileName = ipcsec.ControlSocketFileName
)

func controlTransparent(clientIP net.IP, outIface string) func(network, address string, c syscall.RawConn) error {
	return socketio.ControlTransparent(clientIP, outIface)
}

func canSkipManagedNetworkAddrReload(managedNetworks []ManagedNetwork, reservations []ManagedNetworkReservation) bool {
	return managednet.CanSkipAddrReload(
		toManagedNetManagedNetworks(managedNetworks),
		toManagedNetManagedNetworkReservations(reservations),
	)
}

func setSysProcAttr(cmd *exec.Cmd) {
	procrun.SetSysProcAttr(cmd)
}

func ensureTransparentRouting() {
	tproxysetup.EnsureRouting()
}

func cleanupTransparentRouting() {
	tproxysetup.CleanupRouting()
}

func prepareSecureIPCListener(exePath string) (net.Listener, string, error) {
	return ipcsec.PrepareSecureIPCListener(exePath)
}

func cleanupSecureIPCListener(sockPath string) {
	ipcsec.CleanupSecureIPCListener(sockPath)
}

func validateIPCPeerProcess(conn net.Conn, expectedPID int) error {
	return ipcsec.ValidateIPCPeerProcess(conn, expectedPID)
}

func udpReplyKey(src *net.UDPAddr, reply udpReplyInfo) string {
	return socketio.ReplyKey(src, reply)
}

func udpReplyInfoHasSourceIP(info udpReplyInfo) bool {
	return socketio.ReplyInfoHasSourceIP(info)
}

func controlBindToDevice(iface string) func(network, address string, c syscall.RawConn) error {
	return socketio.ControlBindToDevice(iface)
}

func resolveDialSourceIP(sourceIP string) (net.IP, error) {
	return socketio.ResolveDialSourceIP(sourceIP)
}

func configureOutboundTCPDialer(dialer *net.Dialer, outIface, sourceIP string) error {
	return socketio.ConfigureOutboundTCPDialer(dialer, outIface, sourceIP)
}

func dialOutboundUDP(targetAddr *net.UDPAddr, outIface, sourceIP string) (*net.UDPConn, error) {
	return socketio.DialOutboundUDP(targetAddr, outIface, sourceIP, udpSocketBufferSize)
}

func configureUDPConnBuffers(conn *net.UDPConn) error {
	return socketio.ConfigureUDPConnBuffers(conn, udpSocketBufferSize)
}

func enableUDPReplyPacketInfo(conn *net.UDPConn) error {
	return socketio.EnableUDPReplyPacketInfo(conn)
}

func udpReplyPacketInfoBufferSize() int {
	return socketio.UDPReplyPacketInfoBufferSize()
}

func readUDPWithReplyInfo(conn *net.UDPConn, payload []byte, oob []byte) (int, *net.UDPAddr, udpReplyInfo, error) {
	return socketio.ReadUDPWithReplyInfo(conn, payload, oob)
}

func writeUDPWithReplyInfo(conn *net.UDPConn, payload []byte, dst *net.UDPAddr, info udpReplyInfo) (int, error) {
	return socketio.WriteUDPWithReplyInfo(conn, payload, dst, info)
}
