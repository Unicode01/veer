package app

import (
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestBuildManagedNetworkPersistedBridgeBlock(t *testing.T) {
	block, err := buildManagedNetworkPersistedBridgeBlock(managedNetworkPersistedBridgeSpec{
		Name:            "vmbr9",
		BridgeMTU:       9000,
		BridgeVLANAware: true,
		HardwareAddr:    net.HardwareAddr{0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee},
	})
	if err != nil {
		t.Fatalf("buildManagedNetworkPersistedBridgeBlock() error = %v", err)
	}

	wantLines := []string{
		"# BEGIN forward managed bridge vmbr9",
		"auto vmbr9",
		"iface vmbr9 inet manual",
		"\tbridge-ports none",
		"\tbridge-stp off",
		"\tbridge-fd 0",
		"\thwaddress ether 02:aa:bb:cc:dd:ee",
		"\tmtu 9000",
		"\tbridge-vlan-aware yes",
		"# END forward managed bridge vmbr9",
	}
	for _, line := range wantLines {
		if !strings.Contains(block, line+"\n") {
			t.Fatalf("block missing %q:\n%s", line, block)
		}
	}
}

func TestAppendManagedNetworkBridgeBlockSkipsExistingInterfaceDefinition(t *testing.T) {
	content := "auto vmbr9\niface vmbr9 inet manual\n\tbridge-ports none\n"
	updated, existed, err := appendManagedNetworkBridgeBlock(content, managedNetworkPersistedBridgeSpec{
		Name:         "vmbr9",
		HardwareAddr: net.HardwareAddr{0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee},
	})
	if err != nil {
		t.Fatalf("appendManagedNetworkBridgeBlock() error = %v", err)
	}
	if !existed {
		t.Fatal("existed = false, want true")
	}
	if updated != content {
		t.Fatalf("updated content changed unexpectedly:\n%s", updated)
	}
}

func TestManagedNetworkInterfacesDirectivePathsIncludesSourceAndSourceDirectory(t *testing.T) {
	baseDir := t.TempDir()
	mainPath := filepath.Join(baseDir, "interfaces")
	sourceDir := filepath.Join(baseDir, "interfaces.d")
	if err := os.Mkdir(sourceDir, 0o755); err != nil {
		t.Fatalf("Mkdir(%q) error = %v", sourceDir, err)
	}

	extraA := filepath.Join(baseDir, "extra-a.cfg")
	extraB := filepath.Join(baseDir, "extra-b.cfg")
	dirA := filepath.Join(sourceDir, "10-vmbr0.cfg")
	dirB := filepath.Join(sourceDir, "20-vmbr1.cfg")
	for _, path := range []string{extraA, extraB, dirA, dirB} {
		if err := os.WriteFile(path, []byte("# test\n"), 0o644); err != nil {
			t.Fatalf("WriteFile(%q) error = %v", path, err)
		}
	}

	content := strings.Join([]string{
		"source extra-*.cfg",
		"source-directory interfaces.d",
	}, "\n")
	got := managedNetworkInterfacesDirectivePaths(mainPath, content)
	want := []string{extraA, extraB, dirA, dirB}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("managedNetworkInterfacesDirectivePaths() = %v, want %v", got, want)
	}
}
