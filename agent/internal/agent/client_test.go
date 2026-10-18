package agent

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestTransportTrustAndRevocation(t *testing.T) {
	var status atomic.Int32
	status.Store(200)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+string(makeToken()) {
			t.Error("wrong credential header")
		}
		if status.Load() == 302 {
			w.Header().Set("Location", "https://example.invalid/")
		}
		w.WriteHeader(int(status.Load()))
		if status.Load() == 200 {
			json.NewEncoder(w).Encode(testPolicy())
		}
	}))
	defer server.Close()
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	if _, err := NewClient("http://127.0.0.1", ca); err == nil {
		t.Fatal("HTTP accepted")
	}
	client, err := NewClient(server.URL, ca)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = client.Policy(context.Background(), string(makeToken())); err != nil {
		t.Fatal(err)
	}
	status.Store(401)
	if _, err = client.Policy(context.Background(), string(makeToken())); !IsCredentialRejected(err) {
		t.Fatalf("401 not recognized: %v", err)
	}
	status.Store(302)
	if _, err = client.Policy(context.Background(), string(makeToken())); err == nil || IsCredentialRejected(err) {
		t.Fatal("redirect accepted or misclassified")
	}
	badCA := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("invalid")})
	if _, err = NewClient(server.URL, badCA); err == nil {
		t.Fatal("invalid CA accepted")
	}
}
func makeToken() []byte {
	return []byte("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
}
