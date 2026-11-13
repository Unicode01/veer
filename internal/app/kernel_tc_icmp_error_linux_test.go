//go:build linux

package app

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

const (
	icmpErrorHelperEnv       = "FORWARD_ICMP_ERROR_HELPER"
	icmpErrorHelperTargetEnv = "FORWARD_ICMP_ERROR_HELPER_TARGET"
	icmpErrorHelperLocalEnv  = "FORWARD_ICMP_ERROR_HELPER_LOCAL"
	// A connected UDP socket that the peer refuses: the client sends to a
	// closed port of the backend.
	icmpErrorHelperRoleRefusedClient = "refused-client"
	// The client sends one datagram from a fixed port and closes the socket.
	icmpErrorHelperRoleOneShotClient = "one-shot-client"
	// The backend answers the client's mapping after the client closed it.
	icmpErrorHelperRoleRefusedBackend = "refused-backend"
	icmpErrorClosedPort               = 9
	icmpErrorBackendPort              = 40999
	icmpErrorClientPort               = 41999
)

func TestEgressNATICMPErrorHelperProcess(t *testing.T) {
	role := os.Getenv(icmpErrorHelperEnv)
	if role == "" {
		return
	}
	var err error
	switch role {
	case icmpErrorHelperRoleRefusedClient:
		err = runICMPErrorRefusedClient(os.Getenv(icmpErrorHelperTargetEnv))
	case icmpErrorHelperRoleOneShotClient:
		err = runICMPErrorOneShotClient(os.Getenv(icmpErrorHelperLocalEnv), os.Getenv(icmpErrorHelperTargetEnv))
	case icmpErrorHelperRoleRefusedBackend:
		err = runICMPErrorRefusedBackend(os.Getenv(icmpErrorHelperLocalEnv))
	default:
		err = fmt.Errorf("unknown ICMP error helper role %q", role)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
	os.Exit(0)
}

// readRefused sends on a connected socket until a read reports the peer's
// port unreachable.
func readRefused(conn *net.UDPConn, send func() error) error {
	buf := make([]byte, 64)
	var last error
	for attempt := 0; attempt < 5; attempt++ {
		if err := send(); err != nil {
			if errors.Is(err, syscall.ECONNREFUSED) {
				return nil
			}
			return fmt.Errorf("send: %w", err)
		}
		_ = conn.SetReadDeadline(time.Now().Add(time.Second))
		_, err := conn.Read(buf)
		if errors.Is(err, syscall.ECONNREFUSED) {
			return nil
		}
		last = err
	}
	return fmt.Errorf("no port unreachable reached the socket: last read %v", last)
}

func runICMPErrorRefusedClient(target string) error {
	raddr, err := net.ResolveUDPAddr("udp4", target)
	if err != nil {
		return err
	}
	conn, err := net.DialUDP("udp4", nil, raddr)
	if err != nil {
		return err
	}
	defer conn.Close()
	return readRefused(conn, func() error {
		_, err := conn.Write([]byte("anyone there?"))
		return err
	})
}

func runICMPErrorOneShotClient(local, target string) error {
	laddr, err := net.ResolveUDPAddr("udp4", local)
	if err != nil {
		return err
	}
	raddr, err := net.ResolveUDPAddr("udp4", target)
	if err != nil {
		return err
	}
	conn, err := net.DialUDP("udp4", laddr, raddr)
	if err != nil {
		return err
	}
	_, err = conn.Write([]byte("hello, then gone"))
	conn.Close()
	return err
}

func runICMPErrorRefusedBackend(local string) error {
	laddr, err := net.ResolveUDPAddr("udp4", local)
	if err != nil {
		return err
	}
	listener, err := net.ListenUDP("udp4", laddr)
	if err != nil {
		return err
	}
	buf := make([]byte, 64)
	_ = listener.SetReadDeadline(time.Now().Add(10 * time.Second))
	_, peer, err := listener.ReadFromUDP(buf)
	listener.Close()
	if err != nil {
		return fmt.Errorf("wait for the client: %w", err)
	}
	fmt.Fprintf(os.Stderr, "client mapped to %s\n", peer)
	conn, err := net.DialUDP("udp4", laddr, peer)
	if err != nil {
		return err
	}
	defer conn.Close()
	// Let the client close its socket first.
	time.Sleep(300 * time.Millisecond)
	return readRefused(conn, func() error {
		_, err := conn.Write([]byte("are you still there?"))
		return err
	})
}

func startICMPErrorHelper(t *testing.T, ns, role, local, target string) (*exec.Cmd, *bytes.Buffer) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	cmd := exec.CommandContext(ctx, "ip", "netns", "exec", ns, os.Args[0], "-test.run", "^TestEgressNATICMPErrorHelperProcess$", "-test.v=false")
	cmd.Env = append(os.Environ(),
		icmpErrorHelperEnv+"="+role,
		icmpErrorHelperLocalEnv+"="+local,
		icmpErrorHelperTargetEnv+"="+target,
	)
	logs := &bytes.Buffer{}
	cmd.Stdout = logs
	cmd.Stderr = logs
	if err := cmd.Start(); err != nil {
		t.Fatalf("start %s helper: %v", role, err)
	}
	t.Cleanup(func() {
		if cmd.ProcessState == nil && cmd.Process != nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	})
	return cmd, logs
}

// ICMP errors about egress NAT flows reach the host the flow belongs to in
// both directions: a port unreachable from the WAN refuses the LAN client's
// connected socket, and one a LAN host sends refuses the remote host's.
func TestEgressNATTCRelaysICMPErrors(t *testing.T) {
	if os.Getenv(egressNATTestEnableEnv) != "1" {
		t.Skipf("set %s=1 to run Linux egress NAT integration test", egressNATTestEnableEnv)
	}
	if os.Geteuid() != 0 {
		t.Skip("root privileges are required")
	}
	if _, err := exec.LookPath("ip"); err != nil {
		t.Skip("ip command is required")
	}
	for _, natType := range []string{egressNATTypeSymmetric, egressNATTypeFullCone} {
		t.Run(natType, func(t *testing.T) {
			topology := setupEgressNATIntegrationTopology(t)
			seedEgressNATIntegrationNeighbor(t, topology)
			rt := newTCKernelRuleRuntime(&Config{})
			defer rt.Close()
			rule := buildEgressNATSyntheticRule(EgressNAT{
				ID:              1,
				ParentInterface: topology.BridgeIF,
				OutInterface:    topology.UplinkHostIF,
				OutSourceIP:     egressNATUplinkAddr,
				Protocol:        "udp",
				NATType:         natType,
				Enabled:         true,
			}, topology.ChildHostIF, 1, "udp")
			results, err := rt.Reconcile([]Rule{rule})
			if err != nil {
				t.Fatalf("Reconcile() error = %v", err)
			}
			if result := results[rule.ID]; !result.Running || result.Engine != kernelEngineTC || result.Error != "" {
				t.Fatalf("egress NAT result = %+v, want running tc", result)
			}

			t.Run("from the WAN", func(t *testing.T) {
				client, logs := startICMPErrorHelper(t, topology.ClientNS, icmpErrorHelperRoleRefusedClient, "",
					net.JoinHostPort(egressNATBackendAddr, strconv.Itoa(icmpErrorClosedPort)))
				if err := client.Wait(); err != nil {
					t.Fatalf("the LAN client's socket was not refused: %v\n%s", err, logs.String())
				}
			})
			t.Run("from the LAN", func(t *testing.T) {
				backend, backendLogs := startICMPErrorHelper(t, topology.BackendNS, icmpErrorHelperRoleRefusedBackend,
					net.JoinHostPort(egressNATBackendAddr, strconv.Itoa(icmpErrorBackendPort)), "")
				time.Sleep(200 * time.Millisecond)
				client, clientLogs := startICMPErrorHelper(t, topology.ClientNS, icmpErrorHelperRoleOneShotClient,
					net.JoinHostPort(egressNATClientAddr, strconv.Itoa(icmpErrorClientPort)),
					net.JoinHostPort(egressNATBackendAddr, strconv.Itoa(icmpErrorBackendPort)))
				if err := client.Wait(); err != nil {
					t.Fatalf("one-shot client failed: %v\n%s", err, clientLogs.String())
				}
				if err := backend.Wait(); err != nil {
					t.Fatalf("the backend's socket was not refused: %v\n%s", err, backendLogs.String())
				}
				if !strings.Contains(backendLogs.String(), egressNATUplinkAddr+":") {
					t.Fatalf("the backend did not see the client through the NAT address:\n%s", backendLogs.String())
				}
			})
		})
	}
}
