//go:build linux

package app

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Unicode01/veer/internal/store"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
)

func TestPluginNetRecoveryInterfaceFaultsLinuxIntegration(t *testing.T) {
	requirePluginLinuxIntegration(t)
	provider := newPluginControlNetAdmin().(*linuxPluginControlNetAdmin)
	nsName := pluginIntegrationLinkName("vrns")
	ns, err := provider.NamespaceEnsure(pluginControlNetNamespaceRequest{Name: nsName, LoopbackUp: true})
	if err != nil {
		t.Fatal(err)
	}
	defer provider.NamespaceDelete(nsName, ns.Info.Identity)
	host, peer := pluginIntegrationLinkName("vrh"), pluginIntegrationLinkName("vrp")
	defer deletePluginIntegrationLinkQuietly(t, host)
	veth, err := provider.LinkEnsureVeth(pluginControlNetVethRequest{Host: host, Peer: peer, Up: true})
	if err != nil {
		t.Fatal(err)
	}
	peerLink, err := netlink.LinkByName(peer)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := netns.GetFromName(nsName)
	if err != nil {
		t.Fatal(err)
	}
	if err := netlink.LinkSetNsFd(peerLink, int(handle)); err != nil {
		handle.Close()
		t.Fatal(err)
	}
	handle.Close()
	if err := provider.AddrReplace(pluginControlNetAddrRequest{Interface: host, CIDR: "198.18.42.1/32"}); err != nil {
		t.Fatal(err)
	}
	table := 27000
	healthyRoute := pluginControlNetRouteRequest{Dst: "198.18.42.2/32", Dev: host, Table: table, Scope: int(netlink.SCOPE_LINK)}
	healthyRule := pluginControlNetRuleRequest{Family: "ipv4", Priority: table, Table: table, Dst: "198.18.42.2/32"}
	healthyNeigh := pluginControlNetNeighRequest{Interface: host, IP: "198.18.42.2", MAC: veth.Peer.MAC, State: "permanent"}
	for _, apply := range []func() error{
		func() error { return provider.RouteReplace(healthyRoute) }, func() error { return provider.RuleReplace(healthyRule) }, func() error { return provider.NeighReplace(healthyNeigh) },
	} {
		if err := apply(); err != nil {
			t.Fatal(err)
		}
	}
	defer provider.RouteDelete(healthyRoute)
	defer provider.RuleDelete(healthyRule)
	defer provider.NeighDelete(healthyNeigh)
	var tcpListener *net.TCPListener
	var udpListener *net.UDPConn
	if err := linuxPluginRunInNamespace(nsName, func() error {
		if err := provider.AddrReplace(pluginControlNetAddrRequest{Interface: peer, CIDR: "198.18.42.2/32"}); err != nil {
			return err
		}
		if err := provider.LinkSetUp(peer, true); err != nil {
			return err
		}
		if err := provider.RouteReplace(pluginControlNetRouteRequest{Dst: "198.18.42.1/32", Dev: peer, Scope: int(netlink.SCOPE_LINK)}); err != nil {
			return err
		}
		if err := provider.NeighReplace(pluginControlNetNeighRequest{Interface: peer, IP: "198.18.42.1", MAC: veth.Host.MAC, State: "permanent"}); err != nil {
			return err
		}
		var err error
		tcpListener, err = net.ListenTCP("tcp4", &net.TCPAddr{IP: net.ParseIP("198.18.42.2")})
		if err != nil {
			return err
		}
		udpListener, err = net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("198.18.42.2")})
		return err
	}); err != nil {
		if tcpListener != nil {
			tcpListener.Close()
		}
		t.Fatal(err)
	}
	defer tcpListener.Close()
	defer udpListener.Close()
	go func() {
		conn, err := tcpListener.AcceptTCP()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = io.Copy(conn, conn)
	}()
	go func() {
		buf := make([]byte, 256)
		for {
			n, addr, err := udpListener.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if _, err = udpListener.WriteToUDP(buf[:n], addr); err != nil {
				return
			}
		}
	}()
	tcp, err := net.DialTimeout("tcp4", tcpListener.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer tcp.Close()
	udp, err := net.DialTimeout("udp4", udpListener.LocalAddr().String(), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	var exchanges atomic.Uint64
	done, stop := make(chan error, 1), make(chan struct{})
	go func() {
		payload := []byte("healthy-plugin-long-flow")
		buf := make([]byte, len(payload))
		for {
			select {
			case <-stop:
				done <- nil
				return
			default:
			}
			for _, conn := range []net.Conn{tcp, udp} {
				_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
				if _, err := conn.Write(payload); err != nil {
					done <- err
					return
				}
				if _, err := io.ReadFull(conn, buf); err != nil {
					done <- err
					return
				}
				if !bytes.Equal(payload, buf) {
					done <- fmt.Errorf("corrupt echo")
					return
				}
			}
			exchanges.Add(1)
			time.Sleep(time.Millisecond)
		}
	}()
	defer func() {
		close(stop)
		if err := <-done; err != nil {
			t.Errorf("healthy TCP/UDP flow interrupted: %v", err)
		}
	}()
	assertHealthy := func(t *testing.T) {
		t.Helper()
		before := exchanges.Load()
		deadline := time.Now().Add(3 * time.Second)
		for exchanges.Load() <= before && time.Now().Before(deadline) {
			time.Sleep(time.Millisecond)
		}
		if exchanges.Load() <= before {
			t.Fatal("healthy long flows stopped making progress")
		}
		assertPluginNetPolicyTransactionState(t, *provider, healthyRoute, healthyRule, healthyNeigh, true)
	}
	assertHealthy(t)
	for _, kind := range []string{"route", "rule", "neighbor"} {
		for _, scenario := range []string{"down", "mtu_address_change", "removed", "recreated"} {
			t.Run(kind+"/"+scenario, func(t *testing.T) {
				name := pluginIntegrationLinkName("vrbad")
				defer deletePluginIntegrationLinkQuietly(t, name)
				created, err := provider.LinkEnsureDummy(pluginControlNetDummyRequest{Name: name, MTU: 1500, Up: true})
				if err != nil {
					t.Fatal(err)
				}
				link := created.Link
				db := openTestDB(t)
				entry := pluginNetTransactionEntry{Present: true, LinkIdentities: []pluginNetTransactionLinkIdentity{{Name: name, IfIndex: link.IfIndex, Kind: link.Kind, MAC: link.MAC}}}
				metadata := map[string]any{"version": 1, "boot_id": pluginOwnershipBootID, "dev_ifindex": link.IfIndex}
				switch kind {
				case "route":
					req := pluginControlNetRouteRequest{Dst: "203.0.113.0/24", Dev: name, Table: table + 1}
					entry.ResourceType, entry.ResourceKey, entry.RouteRequest = pluginOwnedResourceTypeRoute, pluginControlNetRouteLeaseKey(req), &req
					metadata["current"], metadata["current_present"] = req, true
					if err := provider.RouteReplace(req); err != nil {
						t.Fatal(err)
					}
				case "rule":
					// Same priority as the healthy rule, with a distinct selector and table.
					req := pluginControlNetRuleRequest{Family: "ipv4", Priority: table, Table: table + 1, Dst: "203.0.113.0/24", IIF: name}
					entry.ResourceType, entry.ResourceKey, entry.RuleRequest = pluginOwnedResourceTypeRule, pluginControlNetRuleLeaseKey(req), &req
					metadata["current"], metadata["current_present"] = req, true
					metadata["link_identities"] = []pluginOwnedRouteLinkIdentity{{Dev: name, IfIndex: link.IfIndex, Kind: link.Kind, MAC: link.MAC}}
					defer provider.RuleDelete(req)
					if err := provider.RuleReplace(req); err != nil {
						t.Fatal(err)
					}
				case "neighbor":
					req := pluginControlNetNeighRequest{Interface: name, IP: "192.0.2.9", MAC: "02:00:00:00:00:09", State: "permanent"}
					entry.ResourceType, entry.ResourceKey, entry.NeighRequest = pluginOwnedResourceTypeNeighbor, pluginControlNetNeighLeaseKey(req), &req
					metadata["current"], metadata["current_present"] = req, true
					if err := provider.NeighReplace(req); err != nil {
						t.Fatal(err)
					}
				}
				state, _ := json.Marshal(pluginNetTransactionState{Version: pluginNetTransactionJournalVersion, BootID: pluginOwnershipBootID, Entries: []pluginNetTransactionEntry{entry}})
				if err := store.AddPluginNetTransaction(db, store.PluginNetTransaction{TransactionID: kind, PluginID: "bad", Kind: kind, StateJSON: string(state), StartedCount: 1}); err != nil {
					t.Fatal(err)
				}
				raw, _ := json.Marshal(metadata)
				if err := store.AddPluginOwnedResource(db, store.PluginOwnedResource{PluginID: "bad", ResourceType: entry.ResourceType, ResourceKey: entry.ResourceKey, MetadataJSON: string(raw)}); err != nil {
					t.Fatal(err)
				}
				switch scenario {
				case "down":
					if err := provider.LinkSetUp(name, false); err != nil {
						t.Fatal(err)
					}
				case "mtu_address_change":
					if err := provider.LinkSetMTU(name, 1300); err != nil {
						t.Fatal(err)
					}
					if err := provider.AddrReplace(pluginControlNetAddrRequest{Interface: name, CIDR: "192.0.2.1/24"}); err != nil {
						t.Fatal(err)
					}
				case "removed", "recreated":
					if err := provider.LinkDelete(name); err != nil {
						t.Fatal(err)
					}
					if scenario == "recreated" {
						if _, err := provider.LinkEnsureDummy(pluginControlNetDummyRequest{Name: name, MTU: 1400, Up: true}); err != nil {
							t.Fatal(err)
						}
					}
				}
				if err := recoverPendingPluginNetTransactions(db, provider); err != nil {
					t.Fatal(err)
				}
				assertNoPluginNetTransactions(t, db)
				if kind == "rule" {
					rules, err := provider.RuleSnapshot(*entry.RuleRequest)
					if err != nil || len(rules) != 0 {
						t.Fatalf("stale rule leaked: %+v %v", rules, err)
					}
				}
				assertHealthy(t)
			})
		}
	}
	t.Logf("healthy TCP and UDP long connections completed %d paired exchanges during interface faults", exchanges.Load())
}
