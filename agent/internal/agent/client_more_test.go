package agent

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestTransportAcknowledgementAndNetworkFailures(t *testing.T) {
	var mode atomic.Int32
	event := fixtureEvent(0)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+string(makeToken()) {
			t.Error("wrong credential header")
		}
		switch mode.Load() {
		case 1:
			_ = json.NewEncoder(w).Encode(Acknowledgement{IDs: nil})
		case 2:
			_ = json.NewEncoder(w).Encode(Acknowledgement{IDs: []string{"unknown"}})
		case 3:
			_ = json.NewEncoder(w).Encode(Acknowledgement{IDs: []string{event.ID, event.ID}})
		case 4:
			_, _ = w.Write([]byte(strings.Repeat("a", MaxBatchBytes+1)))
		case 5:
			select {
			case <-r.Context().Done():
			case <-time.After(100 * time.Millisecond):
			}
		case 6:
			w.WriteHeader(500)
		case 7:
			w.WriteHeader(409)
		default:
			_ = json.NewEncoder(w).Encode(Acknowledgement{IDs: []string{event.ID}})
		}
	}))
	defer server.Close()
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	client, err := NewClient(server.URL, ca)
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []int32{1, 2, 3, 4, 6, 7} {
		mode.Store(bad)
		if _, err = client.Upload(context.Background(), string(makeToken()), []Event{event}); err == nil || IsCredentialRejected(err) {
			t.Fatalf("invalid mode %d accepted or misclassified: %v", bad, err)
		}
		if (bad == 7) != IsIntegrityRejected(err) {
			t.Fatalf("integrity rejection classification for mode %d: %v", bad, err)
		}
	}
	mode.Store(5)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err = client.Upload(ctx, string(makeToken()), []Event{event}); err == nil || IsCredentialRejected(err) {
		t.Fatal("timeout accepted or misclassified")
	}
	mode.Store(0)
	if ack, err := client.Upload(context.Background(), string(makeToken()), []Event{event}); err != nil || len(ack.IDs) != 1 || ack.IDs[0] != event.ID {
		t.Fatalf("valid acknowledgement rejected: %+v %v", ack, err)
	}
	other := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer other.Close()
	wrongCA := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: other.Certificate().Raw})
	wrongClient, err := NewClient(server.URL, wrongCA)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = wrongClient.Policy(context.Background(), string(makeToken())); err == nil || IsCredentialRejected(err) {
		t.Fatal("untrusted TLS endpoint accepted or classified as revocation")
	}
}
