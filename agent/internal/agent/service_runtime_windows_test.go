package agent

import (
	"os"
	"path/filepath"
	"testing"
)

func TestConfigRejectsUntrustedLocationsAndEndpoint(t *testing.T) {
	root := t.TempDir()
	ca := filepath.Join(root, "agent-ca.crt")
	if err := os.WriteFile(ca, []byte("certificate fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	valid := Config{Endpoint: "https://192.0.2.10:8443", TrustPath: ca, DataDirectory: filepath.Join(root, "data"), UserSID: "S-1-5-21-1-2-3-1001", ServicePath: filepath.Join(root, "CherrySecurityAgent.exe")}
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	invalid := valid
	invalid.Endpoint = "http://192.0.2.10:8443"
	if invalid.Validate() == nil {
		t.Fatal("plaintext endpoint accepted")
	}
	invalid = valid
	invalid.DataDirectory = root + `\data\..\escape`
	if invalid.Validate() == nil {
		t.Fatal("unclean data path accepted")
	}
}
