//go:build linux

package app

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"testing"
	"time"
)

func TestEgressNATTCSubsetOverridesIntegration(t *testing.T) {
	if os.Getenv(egressNATTestEnableEnv) != "1" {
		t.Skipf("set %s=1 to run Linux subset orchestration integration test", egressNATTestEnableEnv)
	}
	if os.Geteuid() != 0 {
		t.Skip("root privileges are required")
	}
	if _, err := exec.LookPath("ip"); err != nil {
		t.Skip("ip command is required")
	}
	harness := startEgressNATIntegrationHarness(t, "subset-overrides")
	topology := harness.Topology
	const selectedSource = "198.19.0.9"
	mustRunDataplanePerfCmd(t, "ip", "addr", "add", selectedSource+"/24", "dev", topology.UplinkHostIF)

	// A second downstream device shares the bridge and keeps the default exit.
	other := topology
	other.ClientNS = topology.ClientNS + "s"
	other.ChildHostIF = truncateIfName(topology.ChildHostIF + "s")
	other.ClientNSIF = truncateIfName(topology.ClientNSIF + "s")
	t.Cleanup(func() {
		runDataplanePerfCmd("ip", "link", "del", other.ChildHostIF)
		runDataplanePerfCmd("ip", "netns", "del", other.ClientNS)
	})
	mustRunDataplanePerfCmd(t, "ip", "netns", "add", other.ClientNS)
	mustRunDataplanePerfCmd(t, "ip", "link", "add", other.ChildHostIF, "type", "veth", "peer", "name", other.ClientNSIF)
	mustRunDataplanePerfCmd(t, "ip", "link", "set", other.ChildHostIF, "master", topology.BridgeIF)
	mustRunDataplanePerfCmd(t, "ip", "link", "set", other.ChildHostIF, "up")
	mustRunDataplanePerfCmd(t, "ip", "link", "set", other.ClientNSIF, "netns", other.ClientNS)
	mustRunDataplanePerfCmd(t, "ip", "netns", "exec", other.ClientNS, "ip", "link", "set", "lo", "up")
	mustRunDataplanePerfCmd(t, "ip", "netns", "exec", other.ClientNS, "ip", "addr", "add", "198.18.0.3/24", "dev", other.ClientNSIF)
	mustRunDataplanePerfCmd(t, "ip", "netns", "exec", other.ClientNS, "ip", "link", "set", other.ClientNSIF, "up")
	mustRunDataplanePerfCmd(t, "ip", "netns", "exec", other.ClientNS, "ip", "route", "add", "default", "via", egressNATBridgeAddr)

	createEgressNATIntegrationEntryForScopeWithProtocol(t, harness.APIBase, topology, "", "tcp+udp+icmp")
	waitForEgressNATIntegrationStatus(t, harness.APIBase, topology, "")
	probe := func(client egressNATIntegrationTopology, protocol, expected string) {
		t.Helper()
		if got := runEgressNATIntegrationProbe(t, client, protocol); got != expected {
			logForwardLogOnFailure(t, harness.LogPath)
			t.Fatalf("%s/%s backend saw %s, want %s", client.ChildHostIF, protocol, got, expected)
		}
	}
	probe(topology, "tcp", egressNATUplinkAddr)

	request := func(method, path string, payload any) int {
		t.Helper()
		data, err := json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}
		req, err := http.NewRequest(method, harness.APIBase+path, bytes.NewReader(data))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+egressNATTestToken)
		req.Header.Set("Content-Type", "application/json")
		resp, err := (&http.Client{Timeout: 20 * time.Second}).Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != http.StatusOK {
			t.Logf("%s %s: %s", method, path, body)
		}
		return resp.StatusCode
	}
	childPayload := EgressNAT{ParentInterface: topology.BridgeIF, ChildInterface: topology.ChildHostIF, OutInterface: topology.UplinkHostIF, OutSourceIP: selectedSource, Protocol: "tcp", NATType: egressNATTypeSymmetric, Enabled: true}
	if code := request(http.MethodPost, "/api/egress-nats", childPayload); code != http.StatusOK {
		t.Fatalf("create child override returned %d", code)
	}
	var childID int64
	for _, item := range listEgressNATIntegrationStatuses(t, harness.APIBase) {
		if item.ChildInterface == topology.ChildHostIF {
			childID = item.ID
		}
	}
	if childID == 0 {
		t.Fatal("child override is missing")
	}
	if code := request(http.MethodPost, "/api/egress-nats", childPayload); code != http.StatusBadRequest {
		t.Fatalf("duplicate child returned %d, want conflict validation", code)
	}
	probe(topology, "tcp", selectedSource)
	probe(topology, "udp", egressNATUplinkAddr)
	probe(topology, "icmp", egressNATUplinkAddr)
	probe(other, "tcp", egressNATUplinkAddr)

	toggleEgressNATIntegrationEntry(t, harness.APIBase, childID)
	probe(topology, "tcp", egressNATUplinkAddr)
	toggleEgressNATIntegrationEntry(t, harness.APIBase, childID)
	probe(topology, "tcp", selectedSource)

	// Broaden the child to all protocols, then remove the other bridge member.
	// The parent remains enabled but has no effective targets until it returns.
	childPayload.ID, childPayload.Protocol = childID, "tcp+udp+icmp"
	if code := request(http.MethodPut, "/api/egress-nats", childPayload); code != http.StatusOK {
		t.Fatalf("update child override returned %d", code)
	}
	probe(topology, "udp", selectedSource)
	mustRunDataplanePerfCmd(t, "ip", "link", "set", other.ChildHostIF, "nomaster")
	deadline := time.Now().Add(15 * time.Second)
	covered := false
	for time.Now().Before(deadline) {
		for _, item := range listEgressNATIntegrationStatuses(t, harness.APIBase) {
			if item.ChildInterface == "" && item.Status == "overridden" {
				covered = true
			}
		}
		if covered {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !covered {
		logForwardLogOnFailure(t, harness.LogPath)
		t.Fatal("fully covered default did not enter overridden state")
	}
	if code := request(http.MethodGet, "/readyz", nil); code != http.StatusOK {
		t.Fatalf("fully covered default made healthy child exit unready: %d", code)
	}
	probe(topology, "tcp", selectedSource)
	mustRunDataplanePerfCmd(t, "ip", "link", "set", other.ChildHostIF, "master", topology.BridgeIF)
	waitForEgressNATIntegrationStatus(t, harness.APIBase, topology, "")
	probe(other, "tcp", egressNATUplinkAddr)
	probe(topology, "tcp", selectedSource)

	if code := request(http.MethodDelete, "/api/egress-nats?id="+strconv.FormatInt(childID, 10), nil); code != http.StatusOK {
		t.Fatalf("delete child override returned %d", code)
	}
	probe(topology, "tcp", egressNATUplinkAddr)
	probe(topology, "udp", egressNATUplinkAddr)
}
