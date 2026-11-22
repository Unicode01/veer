package app

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
)

// Frames between the host and veer-plugin-worker. The layout must match
// sdk/native/worker/src/frame.rs: a little-endian u32 length, then
//
//	u8 type, u8 flags, u16 reserved, u32 instance, u64 id, u64 ref,
//	i32 status, u32 name_len, name bytes, payload bytes.
const (
	pluginNativeFrameHeaderLen = 32

	pluginNativeFrameHello     = 1
	pluginNativeFrameLoad      = 2
	pluginNativeFrameLoaded    = 3
	pluginNativeFrameMsg       = 4
	pluginNativeFrameResult    = 5
	pluginNativeFrameCall      = 6
	pluginNativeFrameCallReply = 7
	pluginNativeFrameUnload    = 8
	pluginNativeFrameUnloaded  = 9
	pluginNativeFramePost      = 10
	pluginNativeFrameLog       = 11
	pluginNativeFrameShutdown  = 12

	pluginNativeMaxHostFrameBytes   = pluginHostMaxParentFrameBytes
	pluginNativeMaxWorkerFrameBytes = pluginHostMaxChildFrameBytes
)

// Status codes from veer_plugin.h.
const (
	pluginNativeStatusOK        = 0
	pluginNativeStatusUnhandled = 1
	pluginNativeStatusError     = -1
	pluginNativeStatusInvalid   = -2
	pluginNativeStatusPerm      = -3
	pluginNativeStatusShutdown  = -4
	pluginNativeStatusNoMemory  = -5
)

// Message kinds from veer_msg_kind.
const (
	pluginNativeMsgReconcile       = 1
	pluginNativeMsgDeactivate      = 2
	pluginNativeMsgEvent           = 3
	pluginNativeMsgTimer           = 4
	pluginNativeMsgAction          = 5
	pluginNativeMsgResourceApply   = 6
	pluginNativeMsgResourceMigrate = 7
	pluginNativeMsgEBPFMigrate     = 8
	pluginNativeMsgUpgradeSnapshot = 9
	pluginNativeMsgUpgradeRestore  = 10
	pluginNativeMsgWake            = 11
)

type pluginNativeFrame struct {
	Type      uint8
	Flags     uint8
	Instance  uint32
	ID        uint64
	Reference uint64
	Status    int32
	Name      []byte
	Payload   []byte
}

func pluginNativeMessageKind(eventKind string) uint32 {
	switch eventKind {
	case "reconcile":
		return pluginNativeMsgReconcile
	case "deactivate":
		return pluginNativeMsgDeactivate
	case "event", "socket", "worker":
		// Bus events, socket notifications and ring buffer batches.
		return pluginNativeMsgEvent
	case "timer":
		return pluginNativeMsgTimer
	case "action":
		return pluginNativeMsgAction
	case "resource_apply":
		return pluginNativeMsgResourceApply
	case "resource_migrate":
		return pluginNativeMsgResourceMigrate
	case "ebpf_state_migrate":
		return pluginNativeMsgEBPFMigrate
	case "upgrade_snapshot":
		return pluginNativeMsgUpgradeSnapshot
	case "upgrade_restore":
		return pluginNativeMsgUpgradeRestore
	case "wake":
		return pluginNativeMsgWake
	default:
		return pluginNativeMsgReconcile
	}
}

type pluginNativeFrameReader struct {
	reader *bufio.Reader
	max    int
	header [4 + pluginNativeFrameHeaderLen]byte
}

func newPluginNativeFrameReader(reader io.Reader, maxBytes int) *pluginNativeFrameReader {
	return &pluginNativeFrameReader{reader: bufio.NewReaderSize(reader, 64<<10), max: maxBytes}
}

func (reader *pluginNativeFrameReader) Read() (pluginNativeFrame, error) {
	if _, err := io.ReadFull(reader.reader, reader.header[:]); err != nil {
		return pluginNativeFrame{}, err
	}
	header := reader.header[:]
	length := int(binary.LittleEndian.Uint32(header[0:4]))
	if length < pluginNativeFrameHeaderLen || length > reader.max {
		return pluginNativeFrame{}, fmt.Errorf("plugin worker frame length %d is out of range", length)
	}
	body := header[4:]
	nameLen := int(binary.LittleEndian.Uint32(body[28:32]))
	if nameLen > length-pluginNativeFrameHeaderLen {
		return pluginNativeFrame{}, fmt.Errorf("plugin worker frame name exceeds frame")
	}
	frame := pluginNativeFrame{
		Type:      body[0],
		Flags:     body[1],
		Instance:  binary.LittleEndian.Uint32(body[4:8]),
		ID:        binary.LittleEndian.Uint64(body[8:16]),
		Reference: binary.LittleEndian.Uint64(body[16:24]),
		Status:    int32(binary.LittleEndian.Uint32(body[24:28])),
	}
	rest := make([]byte, length-pluginNativeFrameHeaderLen)
	if _, err := io.ReadFull(reader.reader, rest); err != nil {
		return pluginNativeFrame{}, err
	}
	frame.Name = rest[:nameLen:nameLen]
	frame.Payload = rest[nameLen:]
	return frame, nil
}

// encodePluginNativeFrame builds a frame in one buffer, so it is written
// with a single system call.
func encodePluginNativeFrame(frame pluginNativeFrame) []byte {
	length := pluginNativeFrameHeaderLen + len(frame.Name) + len(frame.Payload)
	out := make([]byte, 4+length)
	binary.LittleEndian.PutUint32(out[0:4], uint32(length))
	body := out[4:]
	body[0] = frame.Type
	body[1] = frame.Flags
	binary.LittleEndian.PutUint32(body[4:8], frame.Instance)
	binary.LittleEndian.PutUint64(body[8:16], frame.ID)
	binary.LittleEndian.PutUint64(body[16:24], frame.Reference)
	binary.LittleEndian.PutUint32(body[24:28], uint32(frame.Status))
	binary.LittleEndian.PutUint32(body[28:32], uint32(len(frame.Name)))
	copy(body[pluginNativeFrameHeaderLen:], frame.Name)
	copy(body[pluginNativeFrameHeaderLen+len(frame.Name):], frame.Payload)
	return out
}
