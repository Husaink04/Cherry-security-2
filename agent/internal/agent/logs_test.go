package agent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBoundedOperationalLog(t *testing.T) {
	path := filepath.Join(t.TempDir(), "service.log")
	log, err := OpenLog(path, 4096)
	if err != nil {
		t.Fatal(err)
	}
	if err = log.Write("application.exe", 1); err == nil {
		t.Fatal("unrecognized payload-like code accepted")
	}
	for i := 0; i < 300; i++ {
		if err = log.Write("network", i); err != nil {
			t.Fatal(err)
		}
	}
	var total int64
	for _, name := range []string{path, path + ".1"} {
		data, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(data), "application.exe") {
			t.Fatal("payload in operational log")
		}
		total += int64(len(data))
	}
	if total > 8192 {
		t.Fatalf("logs exceeded budget: %d", total)
	}
}
