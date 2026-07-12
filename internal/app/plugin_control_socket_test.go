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
	"testing"
	"time"

	"forward/internal/store"
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
	rt := newPluginControlRuntime(db, &Config{}, nil).(*gojaPluginControlRuntime)
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
	rt := newPluginControlRuntime(db, &Config{}, nil).(*gojaPluginControlRuntime)
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
	rt := newPluginControlRuntime(db, &Config{}, nil).(*gojaPluginControlRuntime)
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
			NetAccess:   []PluginNetAccess{{Interfaces: []string{"fwd*"}, Operations: []string{"tcp"}}},
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
	cfg := &Config{PluginsDir: dir}
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
	transport.mu.Lock()
	transport.dials = append(transport.dials, req)
	transport.mu.Unlock()
	transport.peers <- peer
	return client, nil
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
