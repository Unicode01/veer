package app

import (
	"errors"
	"net"
	"time"
)

const (
	pluginControlUDPMaxPayloadBytes = 64 << 10
	pluginControlUDPDefaultTimeout  = time.Second
	pluginControlUDPMaxTimeout      = 30 * time.Second
)

var errPluginControlUDPTimeout = errors.New("udp receive timed out")

type pluginControlUDPTransport interface {
	Send(req pluginControlUDPSendRequest) (pluginControlUDPResult, error)
	Recv(req pluginControlUDPRecvRequest) (pluginControlUDPDatagram, error)
	Exchange(req pluginControlUDPExchangeRequest) (pluginControlUDPDatagram, error)
}

type pluginControlUDPSendRequest struct {
	Namespace  string
	Interface  string
	LocalIP    net.IP
	LocalPort  int
	RemoteIP   net.IP
	RemotePort int
	Payload    []byte
	Timeout    time.Duration
}

type pluginControlUDPRecvRequest struct {
	Namespace       string
	Interface       string
	LocalIP         net.IP
	LocalPort       int
	RemoteIP        net.IP
	RemotePort      int
	HasRemoteFilter bool
	Timeout         time.Duration
	MaxBytes        int
}

type pluginControlUDPExchangeRequest struct {
	Send pluginControlUDPSendRequest
	Recv pluginControlUDPRecvRequest
}

type pluginControlUDPResult struct {
	Namespace  string
	Interface  string
	LocalAddr  *net.UDPAddr
	RemoteAddr *net.UDPAddr
	Bytes      int
}

type pluginControlUDPDatagram struct {
	Namespace  string
	Interface  string
	LocalAddr  *net.UDPAddr
	RemoteAddr *net.UDPAddr
	Payload    []byte
}
