package app

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Unicode01/veer/internal/store"
)

func TestPluginControlPersistentTCPSocketSurvivesHandlers(t *testing.T) {
	db := openTestDB(t)
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "socket_plugin"), 0o755); err != nil {
		t.Fatalf("MkdirAll(socket_plugin) error = %v", err)
	}
	writePluginControlScript(t, dir, "socket_plugin", `
var socketHandle = '';
exports.onAction = function (ctx) {
  var op = ctx.payload.op;
  if (op === 'open') {
    var opened = net.socket.open({
      network: 'tcp4',
      interface: 'eth0',
      remote_ip: '198.51.100.10',
      remote_port: 179,
      timeout_ms: 100
    });
    socketHandle = opened.handle;
    kv.set('opened', {handle: socketHandle, state: opened.state});
    return;
  }
  if (op === 'exchange') {
    var written = net.socket.write({handle: socketHandle, payload_hex: '010203', timeout_ms: 100});
    var reply = net.socket.read({handle: socketHandle, max_bytes: 64, timeout_ms: 100});
    var status = net.socket.status({handle: socketHandle});
    kv.set('exchange', {written: written.bytes, reply: reply.payload_hex, read: status.bytes_read, sent: status.bytes_written});
    return;
  }
  if (op === 'timeout') {
    kv.set('timeout', net.socket.read({handle: socketHandle, max_bytes: 64, timeout_ms: 10}));
    return;
  }
  if (op === 'close') {
    kv.set('closed', net.socket.close({handle: socketHandle}));
    socketHandle = '';
  }
};
`)

	transport := newPluginControlSocketTestTransport()
	rt := newPluginControlRuntime(db, pluginsEnabledTestConfig(&Config{}), nil).(*gojaPluginControlRuntime)
	rt.socketRegistry = newPluginControlSocketRegistry(transport)
	t.Cleanup(func() { _ = rt.Close() })
	plugin := testPersistentSocketPlugin(dir, "socket_plugin", []string{"net.tcp", "kv"}, []string{"tcp"})
	action := PluginAction{ID: "socket"}

	if err := rt.ApplyPluginAction(plugin, action, json.RawMessage(`{"op":"open"}`)); err != nil {
		t.Fatalf("ApplyPluginAction(open) error = %v", err)
	}
	peer := transport.nextPeer(t)
	opened := pluginControlKVDataForTest(t, db, plugin.ID, "opened")
	if opened["state"] != "open" || strings.TrimSpace(opened["handle"].(string)) == "" {
		t.Fatalf("opened = %+v, want persistent open handle", opened)
	}

	serverErr := make(chan error, 1)
	go func() {
		buf := make([]byte, 3)
		if _, err := io.ReadFull(peer, buf); err != nil {
			serverErr <- err
			return
		}
		if string(buf) != "\x01\x02\x03" {
			serverErr <- errors.New("unexpected request payload")
			return
		}
		_, err := peer.Write([]byte{0xaa, 0xbb})
		serverErr <- err
	}()
	if err := rt.ApplyPluginAction(plugin, action, json.RawMessage(`{"op":"exchange"}`)); err != nil {
		t.Fatalf("ApplyPluginAction(exchange) error = %v", err)
	}
	if err := <-serverErr; err != nil {
		t.Fatalf("socket peer exchange error = %v", err)
	}
	exchange := pluginControlKVDataForTest(t, db, plugin.ID, "exchange")
	if exchange["written"] != float64(3) || exchange["reply"] != "aabb" || exchange["read"] != float64(2) || exchange["sent"] != float64(3) {
		t.Fatalf("exchange = %+v, want 3-byte write and aabb reply", exchange)
	}

	if err := rt.ApplyPluginAction(plugin, action, json.RawMessage(`{"op":"timeout"}`)); err != nil {
		t.Fatalf("ApplyPluginAction(timeout) error = %v", err)
	}
	timeoutResult := pluginControlKVDataForTest(t, db, plugin.ID, "timeout")
	if timeoutResult["timeout"] != true || timeoutResult["eof"] != false {
		t.Fatalf("timeout result = %+v, want non-destructive timeout", timeoutResult)
	}
	if got := len(rt.socketRegistry.List(plugin.ID, pluginControlGenerationForTest(t, plugin))); got != 1 {
		t.Fatalf("persistent socket count after timeout = %d, want 1", got)
	}

	if err := rt.ApplyPluginAction(plugin, action, json.RawMessage(`{"op":"close"}`)); err != nil {
		t.Fatalf("ApplyPluginAction(close) error = %v", err)
	}
	closed := pluginControlKVDataForTest(t, db, plugin.ID, "closed")
	if closed["closed"] != true {
		t.Fatalf("closed = %+v, want closed=true", closed)
	}
}

func TestPluginControlPersistentSocketRequiresTCPNetAccess(t *testing.T) {
	db := openTestDB(t)
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "socket_denied"), 0o755); err != nil {
		t.Fatalf("MkdirAll(socket_denied) error = %v", err)
	}
	writePluginControlScript(t, dir, "socket_denied", `
exports.onAction = function () {
  net.socket.open({network: 'tcp4', interface: 'eth0', remote_ip: '198.51.100.10', remote_port: 179});
};
`)
	transport := newPluginControlSocketTestTransport()
	rt := newPluginControlRuntime(db, pluginsEnabledTestConfig(&Config{}), nil).(*gojaPluginControlRuntime)
	rt.socketRegistry = newPluginControlSocketRegistry(transport)
	t.Cleanup(func() { _ = rt.Close() })
	plugin := testPersistentSocketPlugin(dir, "socket_denied", []string{"net.tcp"}, []string{"udp"})

	err := rt.ApplyPluginAction(plugin, PluginAction{ID: "socket"}, json.RawMessage(`{}`))
	if err == nil || !strings.Contains(err.Error(), "net_access operation tcp on interface eth0 is not declared") {
		t.Fatalf("ApplyPluginAction() error = %v, want TCP net_access denial", err)
	}
	if transport.dialCount() != 0 {
		t.Fatalf("transport dial count = %d, want no dial before access check", transport.dialCount())
	}
}

func TestPluginControlPersistentSocketClosesOnDeactivate(t *testing.T) {
	db := openTestDB(t)
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "socket_cleanup"), 0o755); err != nil {
		t.Fatalf("MkdirAll(socket_cleanup) error = %v", err)
	}
	writePluginControlScript(t, dir, "socket_cleanup", `
exports.onAction = function () {
  net.socket.open({network: 'tcp4', interface: 'eth0', remote_ip: '198.51.100.10', remote_port: 179});
};
`)
	transport := newPluginControlSocketTestTransport()
	rt := newPluginControlRuntime(db, pluginsEnabledTestConfig(&Config{}), nil).(*gojaPluginControlRuntime)
	rt.socketRegistry = newPluginControlSocketRegistry(transport)
	t.Cleanup(func() { _ = rt.Close() })
	plugin := testPersistentSocketPlugin(dir, "socket_cleanup", []string{"net.tcp"}, []string{"tcp"})

	if err := rt.ApplyPluginAction(plugin, PluginAction{ID: "socket"}, json.RawMessage(`{}`)); err != nil {
		t.Fatalf("ApplyPluginAction(open) error = %v", err)
	}
	peer := transport.nextPeer(t)
	rt.deactivatePluginControl(plugin.ID)
	if got := len(rt.socketRegistry.List(plugin.ID, pluginControlGenerationForTest(t, plugin))); got != 0 {
		t.Fatalf("socket count after deactivate = %d, want 0", got)
	}
	if err := peer.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		if errors.Is(err, net.ErrClosed) || errors.Is(err, io.ErrClosedPipe) {
			return
		}
		t.Fatalf("peer SetReadDeadline error = %v", err)
	}
	buf := make([]byte, 1)
	if _, err := peer.Read(buf); !errors.Is(err, net.ErrClosed) && !errors.Is(err, io.EOF) {
		t.Fatalf("peer read after deactivate error = %v, want closed connection", err)
	}
}

func TestPluginControlSocketWatchDeliversTCPDataToPersistentWorker(t *testing.T) {
	db := openTestDB(t)
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "socket_watch"), 0o755); err != nil {
		t.Fatalf("MkdirAll(socket_watch) error = %v", err)
	}
	writePluginControlScript(t, dir, "socket_watch", `
var socketHandle = '';
exports.onAction = function () {
  var opened = net.socket.open({network: 'tcp4', interface: 'eth0', remote_ip: '198.51.100.10', remote_port: 179});
  socketHandle = opened.handle;
  net.socket.watch({handle: socketHandle, worker: 'wire', handler: 'onWireData', max_bytes: 4096});
};
exports.onWireData = function (ctx) {
  kv.set('wire', {type: ctx.socket.type, payload: ctx.socket.payload_hex, worker: ctx.worker.name});
  net.socket.write({handle: ctx.socket.socket.handle, payload_hex: 'cc'});
};
`)
	transport := newPluginControlSocketTestTransport()
	rt := newPluginControlRuntime(db, pluginsEnabledTestConfig(&Config{}), nil).(*gojaPluginControlRuntime)
	rt.socketRegistry = newPluginControlSocketRegistry(transport)
	t.Cleanup(func() { _ = rt.Close() })
	plugin := testPersistentSocketPlugin(dir, "socket_watch", []string{"net.tcp", "kv", "worker"}, []string{"tcp"})
	if err := rt.ApplyPluginAction(plugin, PluginAction{ID: "watch"}, json.RawMessage(`{}`)); err != nil {
		t.Fatalf("ApplyPluginAction() error = %v", err)
	}
	peer := transport.nextPeer(t)
	if _, err := peer.Write([]byte{0xaa, 0xbb}); err != nil {
		t.Fatalf("peer.Write() error = %v", err)
	}
	if err := peer.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatalf("peer.SetReadDeadline() error = %v", err)
	}
	reply := make([]byte, 1)
	if _, err := io.ReadFull(peer, reply); err != nil {
		t.Fatalf("peer reply error = %v", err)
	}
	if reply[0] != 0xcc {
		t.Fatalf("peer reply = %x, want cc", reply)
	}
	wire := waitPluginControlKVDataForTest(t, db, plugin.ID, "wire")
	if wire["type"] != "data" || wire["payload"] != "aabb" || wire["worker"] != "wire" {
		t.Fatalf("wire event = %+v", wire)
	}
	generation := pluginControlGenerationForTest(t, plugin)
	deadline := time.Now().Add(3 * time.Second)
	var infos []pluginControlSocketInfo
	for {
		infos = rt.socketRegistry.List(plugin.ID, generation)
		if len(infos) == 1 && infos[0].Watch != nil && infos[0].Watch.Events == 1 {
			break
		}
		if !time.Now().Before(deadline) {
			t.Fatalf("watched socket info = %+v", infos)
		}
		time.Sleep(10 * time.Millisecond)
	}
	if _, err := rt.socketRegistry.Read(plugin.ID, generation, infos[0].Handle, 1, time.Millisecond); err == nil || !strings.Contains(err.Error(), "is watched") {
		t.Fatalf("manual read while watched error = %v", err)
	}
}

func TestPluginControlSocketWatchAcceptsAndWatchesChildConnection(t *testing.T) {
	db := openTestDB(t)
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "socket_service"), 0o755); err != nil {
		t.Fatalf("MkdirAll(socket_service) error = %v", err)
	}
	writePluginControlScript(t, dir, "socket_service", `
exports.onAction = function () {
  var listener = net.socket.listen({network: 'tcp4', interface: 'eth0', local_ip: '127.0.0.1', local_port: 179});
  kv.set('listener', {addr: listener.local_addr});
  net.socket.watch({handle: listener.handle, worker: 'service', handler: 'onAccept'});
};
exports.onAccept = function (ctx) {
  kv.set('accepted', {parent: ctx.socket.socket.handle, child: ctx.socket.accepted.handle});
  net.socket.watch({handle: ctx.socket.accepted.handle, worker: 'service', handler: 'onClientData'});
};
exports.onClientData = function (ctx) {
  kv.set('client', {payload: ctx.socket.payload_hex, parent: ctx.socket.socket.parent_handle});
};
`)
	transport := newPluginControlSocketTestTransport()
	rt := newPluginControlRuntime(db, pluginsEnabledTestConfig(&Config{}), nil).(*gojaPluginControlRuntime)
	rt.socketRegistry = newPluginControlSocketRegistry(transport)
	t.Cleanup(func() { _ = rt.Close() })
	plugin := testPersistentSocketPlugin(dir, "socket_service", []string{"net.tcp", "kv", "worker"}, []string{"tcp"})
	if err := rt.ApplyPluginAction(plugin, PluginAction{ID: "listen"}, json.RawMessage(`{}`)); err != nil {
		t.Fatalf("ApplyPluginAction() error = %v", err)
	}
	listener := pluginControlKVDataForTest(t, db, plugin.ID, "listener")
	client, err := net.DialTimeout("tcp4", listener["addr"].(string), time.Second)
	if err != nil {
		t.Fatalf("DialTimeout() error = %v", err)
	}
	defer client.Close()
	waitPluginControlKVDataForTest(t, db, plugin.ID, "accepted")
	if _, err := client.Write([]byte{0x10, 0x20}); err != nil {
		t.Fatalf("client.Write() error = %v", err)
	}
	data := waitPluginControlKVDataForTest(t, db, plugin.ID, "client")
	if data["payload"] != "1020" || strings.TrimSpace(fmt.Sprint(data["parent"])) == "" {
		t.Fatalf("client event = %+v", data)
	}
}

func TestPluginControlSocketWatchRejectsDatagramWithoutClosingListener(t *testing.T) {
	transport := newPluginControlSocketTestTransport()
	registry := newPluginControlSocketRegistry(transport)
	defer registry.CloseAll()
	listener, err := registry.Listen("udp_watch", "generation-a", pluginControlSocketListenRequest{
		Network: "udp4", Interface: "eth0", LocalIP: net.ParseIP("127.0.0.1"), LocalPort: 5353,
	})
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	delivered := make(chan pluginControlSocketEvent, 1)
	var attempts atomic.Int32
	if _, err := registry.Watch("udp_watch", "generation-a", listener.Handle, pluginControlSocketWatchSpec{
		Worker: "udp", Handler: "onDatagram", MaxBytes: 128,
	}, func(_ pluginControlSocketOwner, _ pluginControlSocketWatchSpec, event pluginControlSocketEvent) error {
		if attempts.Add(1) == 1 {
			return fmt.Errorf("%w: denied test peer", errPluginControlSocketEventRejected)
		}
		delivered <- event
		return nil
	}); err != nil {
		t.Fatalf("Watch() error = %v", err)
	}
	client, err := net.Dial("udp4", listener.LocalAddr)
	if err != nil {
		t.Fatalf("Dial(udp4) error = %v", err)
	}
	defer client.Close()
	if _, err := client.Write([]byte{0x01}); err != nil {
		t.Fatalf("first datagram error = %v", err)
	}
	if _, err := client.Write([]byte{0x02}); err != nil {
		t.Fatalf("second datagram error = %v", err)
	}
	select {
	case event := <-delivered:
		if string(event.Payload) != "\x02" {
			t.Fatalf("delivered payload = %x, want 02", event.Payload)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("allowed datagram was not delivered")
	}
	info, err := registry.Info("udp_watch", "generation-a", listener.Handle)
	if err != nil || info.Watch == nil || info.Watch.Rejected != 1 {
		t.Fatalf("listener after rejection = %+v/%v", info, err)
	}
}

func TestPluginControlSocketWatchTransfersWithGeneration(t *testing.T) {
	transport := newPluginControlSocketTestTransport()
	registry := newPluginControlSocketRegistry(transport)
	defer registry.CloseAll()
	info, err := registry.Open("watch_upgrade", "generation-a", pluginControlSocketOpenRequest{
		Network: "tcp4", Interface: "eth0", RemoteIP: net.ParseIP("198.51.100.1"), RemotePort: 179, Timeout: time.Second,
	})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	peer := transport.nextPeer(t)
	owners := make(chan pluginControlSocketOwner, 1)
	if _, err := registry.Watch("watch_upgrade", "generation-a", info.Handle, pluginControlSocketWatchSpec{
		Worker: "wire", Handler: "onWire", MaxBytes: 64,
	}, func(owner pluginControlSocketOwner, _ pluginControlSocketWatchSpec, _ pluginControlSocketEvent) error {
		owners <- owner
		return nil
	}); err != nil {
		t.Fatalf("Watch() error = %v", err)
	}
	plugin := LoadedPlugin{PluginManifest: PluginManifest{ID: "watch_upgrade", Control: &PluginControl{
		Permissions: []string{"net.tcp", "worker"},
		NetAccess:   []PluginNetAccess{{Interfaces: []string{"eth0"}, Operations: []string{"tcp"}}},
	}}}
	if transferred, err := registry.TransferPluginGeneration(plugin, "generation-a", "generation-b"); err != nil || transferred != 1 {
		t.Fatalf("TransferPluginGeneration() = %d/%v", transferred, err)
	}
	if _, err := peer.Write([]byte{0x42}); err != nil {
		t.Fatalf("peer.Write() error = %v", err)
	}
	select {
	case owner := <-owners:
		if owner.generation != "generation-b" {
			t.Fatalf("watch event generation = %q", owner.generation)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("transferred watcher did not deliver data")
	}
	transferred, err := registry.Info("watch_upgrade", "generation-b", info.Handle)
	if err != nil || transferred.Watch == nil {
		t.Fatalf("transferred socket = %+v/%v", transferred, err)
	}
}

func TestPluginControlPersistentUDPRegistryAndTimeout(t *testing.T) {
	transport := newPluginControlSocketTestTransport()
	registry := newPluginControlSocketRegistry(transport)
	info, err := registry.Open("udp_plugin", "generation-a", pluginControlSocketOpenRequest{
		Network:    "udp4",
		Interface:  "eth0",
		RemoteIP:   net.ParseIP("198.51.100.53"),
		RemotePort: 53,
		Timeout:    100 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("Open(udp4) error = %v", err)
	}
	defer registry.CloseAll()
	if info.Kind != "datagram" {
		t.Fatalf("udp socket kind = %q, want datagram", info.Kind)
	}
	peer := transport.nextPeer(t)

	read, err := registry.Read("udp_plugin", "generation-a", info.Handle, 64, 10*time.Millisecond)
	if err != nil || !read.Timeout {
		t.Fatalf("Read(timeout) = %+v/%v, want timeout", read, err)
	}
	writeDone := make(chan error, 1)
	go func() {
		buf := make([]byte, 2)
		_, err := io.ReadFull(peer, buf)
		if err == nil && string(buf) != "\x10\x20" {
			err = errors.New("unexpected UDP test payload")
		}
		writeDone <- err
	}()
	if _, err := registry.Write("udp_plugin", "generation-a", info.Handle, pluginControlSocketWriteRequest{Payload: []byte{0x10, 0x20}, Timeout: time.Second}); err != nil {
		t.Fatalf("Write(udp4) error = %v", err)
	}
	if err := <-writeDone; err != nil {
		t.Fatalf("UDP peer read error = %v", err)
	}
}

func TestPluginControlPersistentSocketListenAcceptAndDatagramReply(t *testing.T) {
	transport := newPluginControlSocketTestTransport()
	registry := newPluginControlSocketRegistry(transport)
	defer registry.CloseAll()
	defer transport.closePeers()

	listener, err := registry.Listen("server_plugin", "generation-a", pluginControlSocketListenRequest{
		Network:   "tcp4",
		Interface: "eth0",
		LocalIP:   net.ParseIP("127.0.0.1"),
		LocalPort: 179,
		NoDelay:   true,
	})
	if err != nil {
		t.Fatalf("Listen(tcp4) error = %v", err)
	}
	client, err := net.DialTimeout("tcp4", listener.LocalAddr, time.Second)
	if err != nil {
		t.Fatalf("DialTimeout(%s) error = %v", listener.LocalAddr, err)
	}
	defer client.Close()
	accepted, timedOut, err := registry.Accept("server_plugin", "generation-a", listener.Handle, time.Second)
	if err != nil || timedOut {
		t.Fatalf("Accept() = %+v timeout=%t error=%v", accepted, timedOut, err)
	}
	if accepted.ParentHandle != listener.Handle || accepted.Kind != "connection" {
		t.Fatalf("accepted = %+v, want child connection of %s", accepted, listener.Handle)
	}
	if _, err := client.Write([]byte{0x04, 0x05}); err != nil {
		t.Fatalf("TCP client Write error = %v", err)
	}
	read, err := registry.Read("server_plugin", "generation-a", accepted.Handle, 64, time.Second)
	if err != nil || string(read.Payload) != "\x04\x05" {
		t.Fatalf("accepted Read() = %+v/%v, want 0405", read, err)
	}

	packet, err := registry.Listen("server_plugin", "generation-a", pluginControlSocketListenRequest{
		Network:   "udp4",
		Interface: "eth0",
		LocalIP:   net.ParseIP("127.0.0.1"),
		LocalPort: 5353,
	})
	if err != nil {
		t.Fatalf("Listen(udp4) error = %v", err)
	}
	udpClient, err := net.DialTimeout("udp4", packet.LocalAddr, time.Second)
	if err != nil {
		t.Fatalf("DialTimeout(udp4 %s) error = %v", packet.LocalAddr, err)
	}
	defer udpClient.Close()
	if _, err := udpClient.Write([]byte{0x10}); err != nil {
		t.Fatalf("UDP client Write error = %v", err)
	}
	datagram, err := registry.Read("server_plugin", "generation-a", packet.Handle, 64, time.Second)
	if err != nil || string(datagram.Payload) != "\x10" || datagram.RemoteAddr == nil {
		t.Fatalf("datagram Read() = %+v/%v, want payload and peer", datagram, err)
	}
	if _, err := registry.Write("server_plugin", "generation-a", packet.Handle, pluginControlSocketWriteRequest{
		Payload:    []byte{0x20},
		RemoteAddr: datagram.RemoteAddr,
		Timeout:    time.Second,
	}); err != nil {
		t.Fatalf("datagram Write() error = %v", err)
	}
	if err := udpClient.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("UDP client SetReadDeadline error = %v", err)
	}
	buf := make([]byte, 1)
	if _, err := io.ReadFull(udpClient, buf); err != nil || buf[0] != 0x20 {
		t.Fatalf("UDP client reply = %x/%v, want 20", buf, err)
	}
}

func TestPluginManifestPersistentTCPPermission(t *testing.T) {
	manifest := PluginManifest{
		APIVersion: "v1",
		ID:         "bgp_control",
		Name:       "BGP Control",
		Version:    "0.1.0",
		Kind:       "control",
		Control: &PluginControl{
			Main:        "control.js",
			Permissions: []string{"net.tcp"},
			NetAccess:   []PluginNetAccess{{Interfaces: []string{"veer*"}, Operations: []string{"tcp"}}},
		},
	}
	if err := normalizePluginManifest(&manifest); err != nil {
		t.Fatalf("normalizePluginManifest(net.tcp) error = %v", err)
	}
	manifest.Control.Permissions = []string{"net.udp"}
	if err := normalizePluginManifest(&manifest); err == nil || !strings.Contains(err.Error(), "requires net.tcp permission") {
		t.Fatalf("normalizePluginManifest(tcp without permission) error = %v, want permission denial", err)
	}
}

func TestPluginControlPersistentSocketRejectsLateDialAfterGenerationClose(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	peerReady := make(chan net.Conn, 1)
	transport := newPluginControlSocketTestTransport()
	transport.dialFunc = func(context.Context, pluginControlSocketOpenRequest) (net.Conn, error) {
		close(started)
		<-release
		client, peer := net.Pipe()
		peerReady <- peer
		return client, nil
	}
	registry := newPluginControlSocketRegistry(transport)
	defer registry.CloseAll()

	result := make(chan error, 1)
	go func() {
		_, err := registry.Open("reload_plugin", "generation-a", pluginControlSocketOpenRequest{
			Network:    "tcp4",
			Interface:  "eth0",
			RemoteIP:   net.ParseIP("198.51.100.1"),
			RemotePort: 179,
			Timeout:    time.Second,
		})
		result <- err
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("dial did not start")
	}
	registry.ClosePluginGeneration("reload_plugin", "generation-a")
	close(release)
	if err := <-result; !errors.Is(err, errPluginRuntimeTargetNotLoaded) {
		t.Fatalf("late Open() error = %v, want stale generation rejection", err)
	}
	peer := <-peerReady
	defer peer.Close()
	if err := peer.SetReadDeadline(time.Now().Add(time.Second)); err == nil {
		buf := make([]byte, 1)
		if _, err := peer.Read(buf); !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrClosedPipe) && !errors.Is(err, net.ErrClosed) {
			t.Fatalf("late dial peer read error = %v, want closed connection", err)
		}
	} else if !errors.Is(err, io.ErrClosedPipe) && !errors.Is(err, net.ErrClosed) {
		t.Fatalf("late dial peer deadline error = %v, want closed connection", err)
	}
	if got := len(registry.List("reload_plugin", "generation-a")); got != 0 {
		t.Fatalf("stale generation socket count = %d, want 0", got)
	}
}

func TestPluginControlPersistentSocketLimitAndPluginIsolation(t *testing.T) {
	transport := newPluginControlSocketTestTransport()
	registry := newPluginControlSocketRegistry(transport)
	defer registry.CloseAll()
	defer transport.closePeers()
	var first pluginControlSocketInfo
	for i := 0; i < pluginControlSocketMaxPerPlugin; i++ {
		info, err := registry.Open("limited_plugin", "generation-a", pluginControlSocketOpenRequest{
			Network:    "tcp4",
			Interface:  "eth0",
			RemoteIP:   net.ParseIP("198.51.100.1"),
			RemotePort: 179,
			Timeout:    time.Second,
		})
		if err != nil {
			t.Fatalf("Open(%d) error = %v", i, err)
		}
		if i == 0 {
			first = info
		}
	}
	if _, err := registry.Open("limited_plugin", "generation-a", pluginControlSocketOpenRequest{
		Network:    "tcp4",
		Interface:  "eth0",
		RemoteIP:   net.ParseIP("198.51.100.1"),
		RemotePort: 179,
		Timeout:    time.Second,
	}); err == nil || !strings.Contains(err.Error(), "socket limit reached") {
		t.Fatalf("Open(over limit) error = %v, want limit rejection", err)
	}
	if _, err := registry.Info("other_plugin", "generation-a", first.Handle); !errors.Is(err, errPluginControlSocketNotFound) {
		t.Fatalf("cross-plugin Info() error = %v, want hidden handle", err)
	}
	if closed, err := registry.Close("other_plugin", "generation-a", first.Handle); err != nil || closed {
		t.Fatalf("cross-plugin Close() = %t/%v, want no access", closed, err)
	}
}

func TestPluginGojaControlTransactionalUpgradeTransfersPersistentSocket(t *testing.T) {
	dir := t.TempDir()
	writeTestPlugin(t, dir, "socket_upgrade", `{
  "api_version": "v1",
  "id": "socket_upgrade",
  "name": "Socket Upgrade",
  "version": "1.0.0",
  "kind": "control",
  "actions": [{"id": "apply", "runtime_update": "runtime_apply"}],
  "control": {
    "main": "control.js",
    "permissions": ["kv", "net.tcp"],
    "net_access": [{"interfaces": ["eth0"], "operations": ["tcp"]}]
  }
}`)
	writeVersion := func(version int) {
		writePluginControlScript(t, dir, "socket_upgrade", fmt.Sprintf(`
var buildVersion = %d;
var socketHandle = '';
exports.onAction = function (ctx) {
  if (ctx.payload && ctx.payload.open) {
    socketHandle = net.socket.open({network: 'tcp4', interface: 'eth0', remote_ip: '198.51.100.1', remote_port: 179}).handle;
  }
  var status = net.socket.status({handle: socketHandle});
  kv.set('status', {build: buildVersion, handle: socketHandle, state: status.state});
};
exports.onUpgradeSnapshot = function () { return {handle: socketHandle}; };
exports.onUpgradeRestore = function (ctx) { socketHandle = (ctx.upgrade.state || {}).handle || ''; };
`, version))
	}
	writeVersion(1)
	cfg := pluginsEnabledTestConfig(&Config{PluginsDir: dir})
	db := openTestDB(t)
	transport := newPluginControlSocketTestTransport()
	rt := newPluginControlRuntime(db, cfg, nil).(*gojaPluginControlRuntime)
	rt.socketRegistry = newPluginControlSocketRegistry(transport)
	t.Cleanup(func() {
		_ = rt.Close()
		transport.closePeers()
	})
	catalog := loadPluginCatalogWithState(cfg, db)
	applyPluginRuntimeSnapshot(&catalog, rt.Reconcile(catalog))
	plugin := pluginByIDForTest(t, catalog, "socket_upgrade")
	action := pluginActionByIDForTest(t, plugin, "apply")
	if err := rt.ApplyPluginAction(plugin, action, json.RawMessage(`{"open":true}`)); err != nil {
		t.Fatalf("ApplyPluginAction(open) error = %v", err)
	}
	transport.nextPeer(t)
	rt.mu.Lock()
	oldGeneration := rt.controlVMs[plugin.ID].key
	rt.mu.Unlock()
	oldSockets := rt.socketRegistry.List(plugin.ID, oldGeneration)
	if len(oldSockets) != 1 {
		t.Fatalf("old generation socket count = %d, want 1", len(oldSockets))
	}

	writeVersion(2)
	catalog = loadPluginCatalogWithState(cfg, db)
	snapshot := rt.Reconcile(catalog)
	if state, ok := snapshot.stateFor(plugin.ID); !ok || state.Error != "" {
		t.Fatalf("socket upgrade state = %+v ok=%t, want active", state, ok)
	}
	applyPluginRuntimeSnapshot(&catalog, snapshot)
	plugin = pluginByIDForTest(t, catalog, plugin.ID)
	action = pluginActionByIDForTest(t, plugin, "apply")
	rt.mu.Lock()
	newGeneration := rt.controlVMs[plugin.ID].key
	rt.mu.Unlock()
	if oldGeneration == newGeneration {
		t.Fatal("control generation did not change")
	}
	if got := len(rt.socketRegistry.List(plugin.ID, oldGeneration)); got != 0 {
		t.Fatalf("old generation socket count after upgrade = %d, want 0", got)
	}
	newSockets := rt.socketRegistry.List(plugin.ID, newGeneration)
	if len(newSockets) != 1 || newSockets[0].Handle != oldSockets[0].Handle {
		t.Fatalf("new generation sockets = %+v, want inherited handle %s", newSockets, oldSockets[0].Handle)
	}
	if err := rt.ApplyPluginAction(plugin, action, json.RawMessage(`{}`)); err != nil {
		t.Fatalf("ApplyPluginAction(after upgrade) error = %v", err)
	}
	status := pluginControlKVDataForTest(t, db, plugin.ID, "status")
	if int(status["build"].(float64)) != 2 || status["handle"] != oldSockets[0].Handle {
		t.Fatalf("inherited socket status = %+v, want build 2 and handle %s", status, oldSockets[0].Handle)
	}
}

func TestPluginControlSocketGenerationTransferIsAtomicAndPermissionChecked(t *testing.T) {
	transport := newPluginControlSocketTestTransport()
	registry := newPluginControlSocketRegistry(transport)
	defer registry.CloseAll()
	defer transport.closePeers()
	info, err := registry.Open("upgrade_plugin", "generation-a", pluginControlSocketOpenRequest{
		Network:    "tcp4",
		Interface:  "eth0",
		RemoteIP:   net.ParseIP("198.51.100.1"),
		RemotePort: 179,
		Timeout:    time.Second,
	})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	allowed := LoadedPlugin{PluginManifest: PluginManifest{
		ID: "upgrade_plugin",
		Control: &PluginControl{
			Permissions: []string{"net.tcp"},
			NetAccess: []PluginNetAccess{{
				Interfaces: []string{"eth0"},
				Operations: []string{"tcp"},
			}},
		},
	}}
	denied := allowed
	denied.Control = &PluginControl{}
	if _, err := registry.TransferPluginGeneration(denied, "generation-a", "generation-b"); err == nil || !strings.Contains(err.Error(), "net.tcp") {
		t.Fatalf("TransferPluginGeneration(denied) error = %v, want permission rejection", err)
	}
	if _, err := registry.Info("upgrade_plugin", "generation-a", info.Handle); err != nil {
		t.Fatalf("old generation lost socket after rejected transfer: %v", err)
	}
	transferred, err := registry.TransferPluginGeneration(allowed, "generation-a", "generation-b")
	if err != nil || transferred != 1 {
		t.Fatalf("TransferPluginGeneration() = %d/%v, want 1/nil", transferred, err)
	}
	if _, err := registry.Info("upgrade_plugin", "generation-a", info.Handle); !errors.Is(err, errPluginControlSocketNotFound) {
		t.Fatalf("old generation Info() error = %v, want not found", err)
	}
	if got, err := registry.Info("upgrade_plugin", "generation-b", info.Handle); err != nil || got.Handle != info.Handle {
		t.Fatalf("new generation Info() = %+v/%v, want transferred handle", got, err)
	}
}

func TestPluginControlSocketGenerationTransferRejectsPendingOpenWithoutInvalidation(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	peerReady := make(chan net.Conn, 1)
	transport := newPluginControlSocketTestTransport()
	transport.dialFunc = func(context.Context, pluginControlSocketOpenRequest) (net.Conn, error) {
		close(started)
		<-release
		client, peer := net.Pipe()
		peerReady <- peer
		return client, nil
	}
	registry := newPluginControlSocketRegistry(transport)
	defer registry.CloseAll()
	result := make(chan error, 1)
	go func() {
		_, err := registry.Open("upgrade_plugin", "generation-a", pluginControlSocketOpenRequest{
			Network:    "tcp4",
			Interface:  "eth0",
			RemoteIP:   net.ParseIP("198.51.100.1"),
			RemotePort: 179,
			Timeout:    time.Second,
		})
		result <- err
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("dial did not start")
	}
	plugin := LoadedPlugin{PluginManifest: PluginManifest{
		ID: "upgrade_plugin",
		Control: &PluginControl{
			Permissions: []string{"net.tcp"},
			NetAccess:   []PluginNetAccess{{Interfaces: []string{"eth0"}, Operations: []string{"tcp"}}},
		},
	}}
	if _, err := registry.TransferPluginGeneration(plugin, "generation-a", "generation-b"); err == nil || !strings.Contains(err.Error(), "pending socket") {
		t.Fatalf("TransferPluginGeneration(pending) error = %v, want pending rejection", err)
	}
	close(release)
	if err := <-result; err != nil {
		t.Fatalf("Open() after rejected transfer error = %v, want old generation retained", err)
	}
	peer := <-peerReady
	defer peer.Close()
	if got := len(registry.List("upgrade_plugin", "generation-a")); got != 1 {
		t.Fatalf("old generation socket count = %d, want 1", got)
	}
}

func TestPluginControlSocketRejectsMalformedRuntimeRemoteEndpoints(t *testing.T) {
	t.Run("accept", func(t *testing.T) {
		client, peer := net.Pipe()
		defer peer.Close()
		listener := &pluginControlSocketTestListener{conn: &pluginControlSocketRemoteAddrConn{
			Conn: client, remote: pluginControlSocketTestAddr("not-an-ip-endpoint"),
		}}
		transport := &pluginControlSocketEndpointTestTransport{listener: listener}
		registry := newPluginControlSocketRegistry(transport)
		defer registry.CloseAll()
		opened, err := registry.Listen("endpoint_plugin", "generation-a", pluginControlSocketListenRequest{
			Network: "tcp4", Interface: "eth0", LocalIP: net.ParseIP("127.0.0.1"), LocalPort: 179,
		})
		if err != nil {
			t.Fatalf("Listen() error = %v", err)
		}
		if _, _, err := registry.Accept("endpoint_plugin", "generation-a", opened.Handle, time.Second); err == nil || !strings.Contains(err.Error(), "invalid remote endpoint") {
			t.Fatalf("Accept() error = %v, want malformed endpoint rejection", err)
		}
		if got := registry.List("endpoint_plugin", "generation-a"); len(got) != 1 || got[0].Handle != opened.Handle {
			t.Fatalf("sockets after rejected Accept() = %+v, want only listener", got)
		}
	})

	t.Run("datagram read", func(t *testing.T) {
		packet := &pluginControlSocketTestPacketConn{remote: pluginControlSocketTestAddr("bad-peer")}
		transport := &pluginControlSocketEndpointTestTransport{packet: packet}
		registry := newPluginControlSocketRegistry(transport)
		defer registry.CloseAll()
		opened, err := registry.Listen("endpoint_plugin", "generation-a", pluginControlSocketListenRequest{
			Network: "udp4", Interface: "eth0", LocalIP: net.ParseIP("127.0.0.1"), LocalPort: 5353,
		})
		if err != nil {
			t.Fatalf("ListenPacket() error = %v", err)
		}
		if _, err := registry.Read("endpoint_plugin", "generation-a", opened.Handle, 64, time.Second); err == nil || !strings.Contains(err.Error(), "invalid remote endpoint") {
			t.Fatalf("Read() error = %v, want malformed endpoint rejection", err)
		}
		if got := registry.List("endpoint_plugin", "generation-a"); len(got) != 0 {
			t.Fatalf("sockets after rejected datagram = %+v, want closed socket", got)
		}
		if !packet.isClosed() {
			t.Fatal("malformed datagram socket was not closed")
		}
	})

	t.Run("generation transfer", func(t *testing.T) {
		client, peer := net.Pipe()
		defer peer.Close()
		conn := &pluginControlSocketRemoteAddrConn{
			Conn: client, remote: &net.TCPAddr{IP: net.ParseIP("198.51.100.1"), Port: 179},
		}
		transport := &pluginControlSocketEndpointTestTransport{dial: conn}
		registry := newPluginControlSocketRegistry(transport)
		defer registry.CloseAll()
		opened, err := registry.Open("endpoint_plugin", "generation-a", pluginControlSocketOpenRequest{
			Network: "tcp4", Interface: "eth0", RemoteIP: net.ParseIP("198.51.100.1"), RemotePort: 179, Timeout: time.Second,
		})
		if err != nil {
			t.Fatalf("Open() error = %v", err)
		}
		conn.remote = pluginControlSocketTestAddr("corrupt-endpoint")
		plugin := LoadedPlugin{PluginManifest: PluginManifest{ID: "endpoint_plugin", Control: &PluginControl{
			Permissions: []string{"net.tcp"},
			NetAccess:   []PluginNetAccess{{Interfaces: []string{"eth0"}, Operations: []string{"tcp"}}},
		}}}
		if _, err := registry.TransferPluginGeneration(plugin, "generation-a", "generation-b"); err == nil || !strings.Contains(err.Error(), "invalid remote endpoint") {
			t.Fatalf("TransferPluginGeneration() error = %v, want malformed endpoint rejection", err)
		}
		if _, err := registry.Info("endpoint_plugin", "generation-a", opened.Handle); err != nil {
			t.Fatalf("old generation lost socket after rejected transfer: %v", err)
		}
		if _, err := registry.Info("endpoint_plugin", "generation-b", opened.Handle); !errors.Is(err, errPluginControlSocketNotFound) {
			t.Fatalf("new generation acquired rejected socket: %v", err)
		}
	})
}

type pluginControlSocketTestAddr string

func (addr pluginControlSocketTestAddr) Network() string { return "test" }
func (addr pluginControlSocketTestAddr) String() string  { return string(addr) }

type pluginControlSocketRemoteAddrConn struct {
	net.Conn
	remote net.Addr
}

func (conn *pluginControlSocketRemoteAddrConn) RemoteAddr() net.Addr { return conn.remote }

type pluginControlSocketTestListener struct {
	mu     sync.Mutex
	conn   net.Conn
	closed bool
}

func (listener *pluginControlSocketTestListener) Accept() (net.Conn, error) {
	listener.mu.Lock()
	defer listener.mu.Unlock()
	if listener.closed || listener.conn == nil {
		return nil, net.ErrClosed
	}
	conn := listener.conn
	listener.conn = nil
	return conn, nil
}

func (listener *pluginControlSocketTestListener) Close() error {
	listener.mu.Lock()
	defer listener.mu.Unlock()
	listener.closed = true
	if listener.conn != nil {
		err := listener.conn.Close()
		listener.conn = nil
		return err
	}
	return nil
}

func (*pluginControlSocketTestListener) Addr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 179}
}

func (*pluginControlSocketTestListener) SetDeadline(time.Time) error { return nil }

type pluginControlSocketTestPacketConn struct {
	mu     sync.Mutex
	remote net.Addr
	closed bool
}

func (conn *pluginControlSocketTestPacketConn) ReadFrom(payload []byte) (int, net.Addr, error) {
	conn.mu.Lock()
	defer conn.mu.Unlock()
	if conn.closed {
		return 0, nil, net.ErrClosed
	}
	if len(payload) == 0 {
		return 0, conn.remote, nil
	}
	payload[0] = 0x42
	return 1, conn.remote, nil
}

func (*pluginControlSocketTestPacketConn) WriteTo(payload []byte, _ net.Addr) (int, error) {
	return len(payload), nil
}

func (conn *pluginControlSocketTestPacketConn) Close() error {
	conn.mu.Lock()
	conn.closed = true
	conn.mu.Unlock()
	return nil
}

func (*pluginControlSocketTestPacketConn) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 5353}
}

func (*pluginControlSocketTestPacketConn) SetDeadline(time.Time) error      { return nil }
func (*pluginControlSocketTestPacketConn) SetReadDeadline(time.Time) error  { return nil }
func (*pluginControlSocketTestPacketConn) SetWriteDeadline(time.Time) error { return nil }

func (conn *pluginControlSocketTestPacketConn) isClosed() bool {
	conn.mu.Lock()
	defer conn.mu.Unlock()
	return conn.closed
}

type pluginControlSocketEndpointTestTransport struct {
	dial     net.Conn
	listener pluginControlDeadlineListener
	packet   net.PacketConn
}

func (transport *pluginControlSocketEndpointTestTransport) Dial(context.Context, pluginControlSocketOpenRequest) (net.Conn, error) {
	if transport.dial == nil {
		return nil, errors.New("test dial is unavailable")
	}
	return transport.dial, nil
}

func (transport *pluginControlSocketEndpointTestTransport) Listen(context.Context, pluginControlSocketListenRequest) (pluginControlDeadlineListener, error) {
	if transport.listener == nil {
		return nil, errors.New("test listener is unavailable")
	}
	return transport.listener, nil
}

func (transport *pluginControlSocketEndpointTestTransport) ListenPacket(context.Context, pluginControlSocketListenRequest) (net.PacketConn, error) {
	if transport.packet == nil {
		return nil, errors.New("test packet listener is unavailable")
	}
	return transport.packet, nil
}

type pluginControlSocketTestTransport struct {
	mu       sync.Mutex
	peers    chan net.Conn
	dials    []pluginControlSocketOpenRequest
	dialFunc func(context.Context, pluginControlSocketOpenRequest) (net.Conn, error)
}

func newPluginControlSocketTestTransport() *pluginControlSocketTestTransport {
	return &pluginControlSocketTestTransport{peers: make(chan net.Conn, pluginControlSocketMaxPerPlugin+1)}
}

func (transport *pluginControlSocketTestTransport) Dial(ctx context.Context, req pluginControlSocketOpenRequest) (net.Conn, error) {
	if transport.dialFunc != nil {
		return transport.dialFunc(ctx, req)
	}
	client, peer := net.Pipe()
	var remote net.Addr
	if pluginControlSocketIsUDP(req.Network) {
		remote = &net.UDPAddr{IP: append(net.IP(nil), req.RemoteIP...), Port: req.RemotePort}
	} else {
		remote = &net.TCPAddr{IP: append(net.IP(nil), req.RemoteIP...), Port: req.RemotePort}
	}
	transport.mu.Lock()
	transport.dials = append(transport.dials, req)
	transport.mu.Unlock()
	transport.peers <- peer
	return &pluginControlSocketRemoteAddrConn{Conn: client, remote: remote}, nil
}

func (*pluginControlSocketTestTransport) Listen(_ context.Context, req pluginControlSocketListenRequest) (pluginControlDeadlineListener, error) {
	listener, err := net.Listen(req.Network, "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	deadlineListener, ok := listener.(pluginControlDeadlineListener)
	if !ok {
		_ = listener.Close()
		return nil, errors.New("test listener does not support deadlines")
	}
	return deadlineListener, nil
}

func (*pluginControlSocketTestTransport) ListenPacket(_ context.Context, req pluginControlSocketListenRequest) (net.PacketConn, error) {
	return net.ListenPacket(req.Network, "127.0.0.1:0")
}

func (transport *pluginControlSocketTestTransport) nextPeer(t *testing.T) net.Conn {
	t.Helper()
	select {
	case peer := <-transport.peers:
		t.Cleanup(func() { _ = peer.Close() })
		return peer
	case <-time.After(time.Second):
		t.Fatal("persistent socket transport did not dial")
		return nil
	}
}

func (transport *pluginControlSocketTestTransport) dialCount() int {
	transport.mu.Lock()
	defer transport.mu.Unlock()
	return len(transport.dials)
}

func (transport *pluginControlSocketTestTransport) closePeers() {
	for {
		select {
		case peer := <-transport.peers:
			_ = peer.Close()
		default:
			return
		}
	}
}

func testPersistentSocketPlugin(dir string, id string, permissions []string, operations []string) LoadedPlugin {
	return LoadedPlugin{
		PluginManifest: PluginManifest{
			APIVersion: "v1",
			ID:         id,
			Name:       "Socket Test",
			Version:    "0.1.0",
			Kind:       "control",
			Stability:  pluginStabilityStable,
			Control: &PluginControl{
				Main:        "control.js",
				Permissions: permissions,
				NetAccess:   []PluginNetAccess{{Interfaces: []string{"eth*"}, Operations: operations}},
			},
		},
		Status:          pluginStatusActive,
		controlMainPath: filepath.Join(dir, id, "control.js"),
	}
}

func pluginControlGenerationForTest(t *testing.T, plugin LoadedPlugin) string {
	t.Helper()
	generation, err := pluginControlVMKey(plugin, "control", "")
	if err != nil {
		t.Fatalf("pluginControlVMKey() error = %v", err)
	}
	return generation
}

func pluginControlKVDataForTest(t *testing.T, db *sql.DB, pluginID string, key string) map[string]any {
	t.Helper()
	record, err := store.GetPluginRecord(db, pluginID, pluginControlKVResourceID, key)
	if err != nil {
		t.Fatalf("GetPluginRecord(%s) error = %v", key, err)
	}
	var out map[string]any
	if err := json.Unmarshal([]byte(record.DataJSON), &out); err != nil {
		t.Fatalf("Unmarshal(%s) error = %v", key, err)
	}
	return out
}

func waitPluginControlKVDataForTest(t *testing.T, db *sql.DB, pluginID string, key string) map[string]any {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		record, err := store.GetPluginRecord(db, pluginID, pluginControlKVResourceID, key)
		if err == nil {
			var out map[string]any
			if err := json.Unmarshal([]byte(record.DataJSON), &out); err != nil {
				t.Fatalf("Unmarshal(%s) error = %v", key, err)
			}
			return out
		}
		if !errors.Is(err, sql.ErrNoRows) {
			t.Fatalf("GetPluginRecord(%s) error = %v", key, err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("plugin KV %s/%s was not written", pluginID, key)
	return nil
}
