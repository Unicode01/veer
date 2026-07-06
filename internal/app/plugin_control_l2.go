package app

import (
	"errors"
	"time"
)

const (
	pluginControlL2MaxPayloadBytes = 64 << 10
	pluginControlL2DefaultTimeout  = 100 * time.Millisecond
	pluginControlL2MaxTimeout      = 1500 * time.Millisecond
	pluginControlL2MaxRecvFrames   = 64
)

var errPluginControlL2Timeout = errors.New("raw l2 receive timed out")

type pluginControlL2Transport interface {
	Send(req pluginControlL2SendRequest) error
	Recv(req pluginControlL2RecvRequest) (pluginControlL2Frame, error)
	RecvMany(req pluginControlL2RecvManyRequest) ([]pluginControlL2Frame, error)
	Exchange(req pluginControlL2ExchangeRequest) (pluginControlL2Frame, error)
	ExchangeMany(req pluginControlL2ExchangeManyRequest) ([]pluginControlL2Frame, error)
}

type pluginControlL2SendRequest struct {
	Interface string
	EtherType uint16
	DstMAC    [6]byte
	SrcMAC    [6]byte
	HasSrcMAC bool
	Payload   []byte
}

type pluginControlL2RecvRequest struct {
	Interface string
	EtherType uint16
	Timeout   time.Duration
	MaxBytes  int
}

type pluginControlL2ExchangeRequest struct {
	Send pluginControlL2SendRequest
	Recv pluginControlL2RecvRequest
}

type pluginControlL2ExchangeManyRequest struct {
	Send pluginControlL2SendRequest
	Recv pluginControlL2RecvManyRequest
}

type pluginControlL2RecvManyRequest struct {
	Recv        pluginControlL2RecvRequest
	MaxFrames   int
	IdleTimeout time.Duration
}

type pluginControlL2Frame struct {
	Interface string
	IfIndex   int
	EtherType uint16
	DstMAC    [6]byte
	SrcMAC    [6]byte
	Payload   []byte
	Frame     []byte
}
