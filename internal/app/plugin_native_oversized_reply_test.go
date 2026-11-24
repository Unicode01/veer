package app

import (
	"bytes"
	"net"
	"strings"
	"testing"
	"time"
)

// A host call result too large for one message used to fail the exchange
// while the worker kept waiting for the reply, so it refused every later
// message as nested until it restarted.
func TestNativeExchangeFailsAnOversizedHostResultAndKeepsServing(t *testing.T) {
	host, worker := net.Pipe()
	defer host.Close()
	defer worker.Close()
	instance := &pluginNativeInstance{
		id:       7,
		pluginID: "oversized",
		conn:     host,
		reader:   newPluginNativeFrameReader(host, pluginNativeMaxWorkerFrameBytes),
	}

	type outcome struct {
		status  int32
		payload []byte
		err     string
	}
	replies := make(chan outcome, 2)
	go func() {
		reader := newPluginNativeFrameReader(worker, pluginNativeMaxHostFrameBytes)
		for round := 0; round < 2; round++ {
			msg, err := reader.Read()
			if err != nil || msg.Type != pluginNativeFrameMsg {
				replies <- outcome{err: "worker expected a MSG"}
				return
			}
			if _, err := worker.Write(encodePluginNativeFrame(pluginNativeFrame{
				Type: pluginNativeFrameCall, Instance: msg.Instance, ID: 100 + uint64(round), Reference: msg.ID, Name: []byte("blob.get"),
			})); err != nil {
				replies <- outcome{err: err.Error()}
				return
			}
			reply, err := reader.Read()
			if err != nil || reply.Type != pluginNativeFrameCallReply || reply.Reference != 100+uint64(round) {
				replies <- outcome{err: "worker expected the call reply"}
				return
			}
			replies <- outcome{status: reply.Status, payload: reply.Payload}
			if _, err := worker.Write(encodePluginNativeFrame(pluginNativeFrame{
				Type: pluginNativeFrameResult, Instance: msg.Instance, Reference: msg.ID, Status: pluginNativeStatusOK,
			})); err != nil {
				return
			}
		}
	}()

	huge := bytes.Repeat([]byte("x"), pluginNativeMaxHostFrameBytes)
	calls := func(method string, _ []byte) (int32, []byte) { return pluginNativeStatusOK, huge }
	deadline := time.Now().Add(30 * time.Second)
	if status, _, err := instance.exchange(1, "onAction", nil, calls, deadline); err != nil || status != pluginNativeStatusOK {
		t.Fatalf("first exchange = %d, %v; want the handler's result", status, err)
	}
	first := <-replies
	if first.err != "" || first.status != pluginNativeStatusError || !strings.Contains(string(first.payload), "more than one plugin message carries") {
		t.Fatalf("oversized reply = %+v (%s), want an error reply", first.status, first.payload)
	}

	small := func(string, []byte) (int32, []byte) { return pluginNativeStatusOK, []byte(`{"ok":true}`) }
	if status, _, err := instance.exchange(1, "onAction", nil, small, deadline); err != nil || status != pluginNativeStatusOK {
		t.Fatalf("second exchange = %d, %v; want the instance to keep working", status, err)
	}
	if second := <-replies; second.err != "" || second.status != pluginNativeStatusOK || string(second.payload) != `{"ok":true}` {
		t.Fatalf("second reply = %+v (%s)", second.status, second.payload)
	}
}
