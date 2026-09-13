package app

import (
	"errors"
	"io"
	"sync"
	"testing"
	"time"
)

func TestPluginHostBlockedWritesRespectCancellation(t *testing.T) {
	for _, mode := range []string{"deadline", "interrupt", "close", "close_during_send"} {
		t.Run(mode, func(t *testing.T) {
			reader, writer := io.Pipe()
			pipe := &pluginHostTestPipe{WriteCloser: writer, done: make(chan struct{})}
			client := &pluginHostClient{stdin: pipe, done: pipe.done, errors: make(chan error, 4), messages: make(chan pluginHostMessage)}
			t.Cleanup(func() { _ = reader.Close(); _ = pipe.Close() })
			finished := make(chan error, 1)
			if mode == "close_during_send" {
				go func() { _ = client.send(pluginHostMessage{Type: pluginHostMessageTypeEvent}) }()
				// Consume the header; the frame body now blocks while holding writeMu.
				var header [4]byte
				if _, err := io.ReadFull(reader, header[:]); err != nil {
					t.Fatal(err)
				}
			}
			go func() {
				switch mode {
				case "deadline":
					_, err := client.runEvent(pluginHostEventRequest{Handler: "onAction"}, nil, time.Now().Add(50*time.Millisecond), false)
					finished <- err
				case "interrupt":
					client.Interrupt("test cancellation")
					finished <- nil
				default:
					client.Close()
					finished <- nil
				}
			}()
			select {
			case err := <-finished:
				if mode == "deadline" && !errors.Is(err, errPluginHostProcessExited) {
					t.Fatalf("deadline error = %v", err)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("blocked IPC did not terminate")
			}
		})
	}
}

// Model Wait reaping the child when its pipe is forcibly closed.
type pluginHostTestPipe struct {
	io.WriteCloser
	done chan struct{}
	once sync.Once
}

func (pipe *pluginHostTestPipe) Close() error {
	err := pipe.WriteCloser.Close()
	pipe.once.Do(func() { close(pipe.done) })
	return err
}
