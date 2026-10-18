package agent

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
)

func TestDeliveryIsolatesOneRejectedEvent(t *testing.T) {
	// 409 conflicts must be isolated like validation errors instead of blocking the queue.
	for _, status := range []int{400, 409} {
		t.Run(http.StatusText(status), func(t *testing.T) { deliverWithOneRejection(t, status) })
	}
}

func deliverWithOneRejection(t *testing.T, status int) {
	queue, err := OpenQueue(filepath.Join(t.TempDir(), "deliver.db"), QueueLimit)
	if err != nil {
		t.Fatal(err)
	}
	defer queue.Close()
	events := []Event{fixtureEvent(0), fixtureEvent(1), fixtureEvent(2)}
	if err = queue.CommitObservation("fixture", NewTimeline(testPolicy()).Checkpoint(), events); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var input struct {
			Events []Event `json:"events"`
		}
		if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
			t.Error(err)
			return
		}
		accepted := []string{}
		for _, event := range input.Events {
			if event.ID == events[1].ID {
				w.WriteHeader(status)
				return
			}
			accepted = append(accepted, event.ID)
		}
		_ = json.NewEncoder(w).Encode(Acknowledgement{IDs: accepted})
	}))
	defer server.Close()
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	client, err := NewClient(server.URL, ca)
	if err != nil {
		t.Fatal(err)
	}
	if err = DeliverOnce(context.Background(), queue, client, string(makeToken())); err != nil {
		t.Fatal(err)
	}
	stats := queue.Stats()
	if stats.Events != 0 || stats.LostEvents != 1 {
		t.Fatalf("wrong delivery/loss state: %+v", stats)
	}
}
