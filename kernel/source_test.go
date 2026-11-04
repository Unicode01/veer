package kernel

import (
	"io/fs"
	"strings"
	"testing"
)

func TestHelperSourceCarriesEverythingTheBuildNeeds(t *testing.T) {
	source := HelperSource()
	for _, name := range []string{"Kbuild", "Makefile", "build.sh", "veer_kfuncs.c"} {
		data, err := fs.ReadFile(source, name)
		if err != nil || len(data) == 0 {
			t.Fatalf("embedded %s: %v", name, err)
		}
		if strings.Contains(string(data), "\r\n") {
			t.Fatalf("embedded %s has CRLF line endings", name)
		}
	}
	script, _ := fs.ReadFile(source, "build.sh")
	if !strings.Contains(string(script), `make -C "$MODULE_DIR"`) {
		t.Fatal("build.sh must build from its own directory so a private copy works")
	}
}
