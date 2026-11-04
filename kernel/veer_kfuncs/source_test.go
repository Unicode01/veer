package veerkfuncs

import (
	"io/fs"
	"strings"
	"testing"
)

func TestSourceCarriesEverythingTheBuildNeeds(t *testing.T) {
	for _, name := range []string{"Kbuild", "Makefile", "build.sh", "veer_kfuncs.c"} {
		data, err := fs.ReadFile(Source, name)
		if err != nil || len(data) == 0 {
			t.Fatalf("embedded %s: %v", name, err)
		}
	}
	script, _ := fs.ReadFile(Source, "build.sh")
	if !strings.Contains(string(script), `make -C "$MODULE_DIR"`) {
		t.Fatal("build.sh must build from its own directory so a private copy works")
	}
}
