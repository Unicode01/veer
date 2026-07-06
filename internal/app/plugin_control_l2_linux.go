//go:build linux

package app

import (
	"encoding/binary"
	"fmt"
	"net"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

func newPluginControlL2Transport() pluginControlL2Transport {
	return linuxPluginControlL2Transport{}
}

type linuxPluginControlL2Transport struct{}

func (linuxPluginControlL2Transport) Send(req pluginControlL2SendRequest) error {
	iface, src, err := resolvePluginControlL2Send(req)
	if err != nil {
		return err
	}

	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, int(htons(req.EtherType)))
	if err != nil {
		return err
	}
	defer unix.Close(fd)

	return sendPluginControlL2Frame(fd, iface.Index, req, src)
}

func (linuxPluginControlL2Transport) Recv(req pluginControlL2RecvRequest) (pluginControlL2Frame, error) {
	fd, iface, err := openPluginControlL2RecvSocket(req)
	if err != nil {
		return pluginControlL2Frame{}, err
	}
	defer unix.Close(fd)
	return recvPluginControlL2Frame(fd, iface, req)
}

func (linuxPluginControlL2Transport) RecvMany(req pluginControlL2RecvManyRequest) ([]pluginControlL2Frame, error) {
	fd, iface, err := openPluginControlL2RecvSocket(req.Recv)
	if err != nil {
		return nil, err
	}
	defer unix.Close(fd)
	return recvManyPluginControlL2Frames(fd, iface, req)
}

func (linuxPluginControlL2Transport) Exchange(req pluginControlL2ExchangeRequest) (pluginControlL2Frame, error) {
	if req.Send.Interface != req.Recv.Interface {
		return pluginControlL2Frame{}, fmt.Errorf("send and receive interface must match")
	}
	if req.Send.EtherType != req.Recv.EtherType {
		return pluginControlL2Frame{}, fmt.Errorf("send and receive ethertype must match")
	}
	fd, iface, err := openPluginControlL2RecvSocket(req.Recv)
	if err != nil {
		return pluginControlL2Frame{}, err
	}
	defer unix.Close(fd)
	_, src, err := resolvePluginControlL2Send(req.Send)
	if err != nil {
		return pluginControlL2Frame{}, err
	}
	if err := sendPluginControlL2Frame(fd, iface.Index, req.Send, src); err != nil {
		return pluginControlL2Frame{}, err
	}
	return recvPluginControlL2Frame(fd, iface, req.Recv)
}

func (linuxPluginControlL2Transport) ExchangeMany(req pluginControlL2ExchangeManyRequest) ([]pluginControlL2Frame, error) {
	if req.Send.Interface != req.Recv.Recv.Interface {
		return nil, fmt.Errorf("send and receive interface must match")
	}
	if req.Send.EtherType != req.Recv.Recv.EtherType {
		return nil, fmt.Errorf("send and receive ethertype must match")
	}
	fd, iface, err := openPluginControlL2RecvSocket(req.Recv.Recv)
	if err != nil {
		return nil, err
	}
	defer unix.Close(fd)
	_, src, err := resolvePluginControlL2Send(req.Send)
	if err != nil {
		return nil, err
	}
	if err := sendPluginControlL2Frame(fd, iface.Index, req.Send, src); err != nil {
		return nil, err
	}
	return recvManyPluginControlL2Frames(fd, iface, req.Recv)
}

func resolvePluginControlL2Send(req pluginControlL2SendRequest) (*net.Interface, [6]byte, error) {
	iface, err := net.InterfaceByName(req.Interface)
	if err != nil {
		return nil, [6]byte{}, fmt.Errorf("resolve interface %q: %w", req.Interface, err)
	}
	src := req.SrcMAC
	if !req.HasSrcMAC {
		if len(iface.HardwareAddr) != 6 {
			return nil, [6]byte{}, fmt.Errorf("interface %q has no ethernet MAC address", req.Interface)
		}
		copy(src[:], iface.HardwareAddr)
	}
	return iface, src, nil
}

func openPluginControlL2RecvSocket(req pluginControlL2RecvRequest) (int, *net.Interface, error) {
	iface, err := net.InterfaceByName(req.Interface)
	if err != nil {
		return -1, nil, fmt.Errorf("resolve interface %q: %w", req.Interface, err)
	}
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, int(htons(req.EtherType)))
	if err != nil {
		return -1, nil, err
	}
	if err := unix.Bind(fd, &unix.SockaddrLinklayer{
		Protocol: htons(req.EtherType),
		Ifindex:  iface.Index,
	}); err != nil {
		_ = unix.Close(fd)
		return -1, nil, err
	}
	return fd, iface, nil
}

func sendPluginControlL2Frame(fd int, ifindex int, req pluginControlL2SendRequest, src [6]byte) error {
	frame := make([]byte, 14+len(req.Payload))
	copy(frame[0:6], req.DstMAC[:])
	copy(frame[6:12], src[:])
	binary.BigEndian.PutUint16(frame[12:14], req.EtherType)
	copy(frame[14:], req.Payload)

	var addr [8]byte
	copy(addr[:], req.DstMAC[:])
	return unix.Sendto(fd, frame, 0, &unix.SockaddrLinklayer{
		Protocol: htons(req.EtherType),
		Ifindex:  ifindex,
		Halen:    6,
		Addr:     addr,
	})
}

func recvPluginControlL2Frame(fd int, iface *net.Interface, req pluginControlL2RecvRequest) (pluginControlL2Frame, error) {
	deadline := time.Now().Add(req.Timeout)
	buf := make([]byte, req.MaxBytes)
	for {
		timeoutMs := int(time.Until(deadline).Milliseconds())
		if timeoutMs <= 0 {
			return pluginControlL2Frame{}, errPluginControlL2Timeout
		}
		pollFDs := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
		n, err := unix.Poll(pollFDs, timeoutMs)
		if err != nil {
			if err == syscall.EINTR {
				continue
			}
			return pluginControlL2Frame{}, err
		}
		if n == 0 {
			return pluginControlL2Frame{}, errPluginControlL2Timeout
		}
		nread, from, err := unix.Recvfrom(fd, buf, 0)
		if err != nil {
			if err == syscall.EINTR || err == syscall.EAGAIN {
				continue
			}
			return pluginControlL2Frame{}, err
		}
		if nread < 14 {
			continue
		}
		ll, _ := from.(*unix.SockaddrLinklayer)
		if ll != nil {
			if ll.Ifindex != iface.Index || ll.Pkttype == unix.PACKET_OUTGOING {
				continue
			}
		}
		etherType := binary.BigEndian.Uint16(buf[12:14])
		if etherType != req.EtherType {
			continue
		}
		var dst, src [6]byte
		copy(dst[:], buf[0:6])
		copy(src[:], buf[6:12])
		frame := append([]byte(nil), buf[:nread]...)
		payload := append([]byte(nil), buf[14:nread]...)
		return pluginControlL2Frame{
			Interface: req.Interface,
			IfIndex:   iface.Index,
			EtherType: etherType,
			DstMAC:    dst,
			SrcMAC:    src,
			Payload:   payload,
			Frame:     frame,
		}, nil
	}
}

func recvManyPluginControlL2Frames(fd int, iface *net.Interface, req pluginControlL2RecvManyRequest) ([]pluginControlL2Frame, error) {
	maxFrames := req.MaxFrames
	if maxFrames <= 0 || maxFrames > pluginControlL2MaxRecvFrames {
		maxFrames = pluginControlL2MaxRecvFrames
	}
	frames := make([]pluginControlL2Frame, 0, maxFrames)
	deadline := time.Now().Add(req.Recv.Timeout)
	idleTimeout := req.IdleTimeout
	if idleTimeout <= 0 || idleTimeout > req.Recv.Timeout {
		idleTimeout = 10 * time.Millisecond
	}
	buf := make([]byte, req.Recv.MaxBytes)
	for len(frames) < maxFrames {
		waitUntil := deadline
		if len(frames) > 0 {
			idleDeadline := time.Now().Add(idleTimeout)
			if idleDeadline.Before(waitUntil) {
				waitUntil = idleDeadline
			}
		}
		timeoutMs := int(time.Until(waitUntil).Milliseconds())
		if timeoutMs <= 0 {
			break
		}
		pollFDs := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
		n, err := unix.Poll(pollFDs, timeoutMs)
		if err != nil {
			if err == syscall.EINTR {
				continue
			}
			return frames, err
		}
		if n == 0 {
			break
		}
		nread, from, err := unix.Recvfrom(fd, buf, 0)
		if err != nil {
			if err == syscall.EINTR || err == syscall.EAGAIN {
				continue
			}
			return frames, err
		}
		if nread < 14 {
			continue
		}
		ll, _ := from.(*unix.SockaddrLinklayer)
		if ll != nil {
			if ll.Ifindex != iface.Index || ll.Pkttype == unix.PACKET_OUTGOING {
				continue
			}
		}
		etherType := binary.BigEndian.Uint16(buf[12:14])
		if etherType != req.Recv.EtherType {
			continue
		}
		var dst, src [6]byte
		copy(dst[:], buf[0:6])
		copy(src[:], buf[6:12])
		frame := append([]byte(nil), buf[:nread]...)
		payload := append([]byte(nil), buf[14:nread]...)
		frames = append(frames, pluginControlL2Frame{
			Interface: req.Recv.Interface,
			IfIndex:   iface.Index,
			EtherType: etherType,
			DstMAC:    dst,
			SrcMAC:    src,
			Payload:   payload,
			Frame:     frame,
		})
	}
	return frames, nil
}

func htons(value uint16) uint16 {
	return (value << 8) | (value >> 8)
}
