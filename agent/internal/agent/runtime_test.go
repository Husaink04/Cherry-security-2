package agent

import (
	"path/filepath"
	"testing"
	"time"
)

func TestEngineAcknowledgesOnlyDurableHelperSamples(t *testing.T) {
	queue, err := OpenQueue(filepath.Join(t.TempDir(), "engine.db"), QueueLimit)
	if err != nil {
		t.Fatal(err)
	}
	defer queue.Close()
	policy := testPolicy()
	engine, err := NewEngine(queue, policy, policy.ServerTime)
	if err != nil {
		t.Fatal(err)
	}
	sample := Sample{At: policy.ServerTime, State: "active", App: "first.exe", Session: "console", Monotonic: 0}
	message := HelperMessage{Version: 1, Nonce: token(), MessageID: token(), HelperInstance: token(), Sequence: 1, Kind: "samples", Samples: []Sample{sample}}
	if err = engine.ObserveMessage(message); err != nil {
		t.Fatal(err)
	}
	first := engine.Checkpoint()
	message.Nonce = token()
	if err = engine.ObserveMessage(message); err != nil {
		t.Fatal(err)
	}
	if engine.Checkpoint().Sequence != first.Sequence {
		t.Fatal("lost reply replay advanced timeline")
	}
	message.Samples[0].App = "changed.exe"
	if err = engine.ObserveMessage(message); err == nil {
		t.Fatal("changed replay accepted")
	}
	message.MessageID = token()
	message.Sequence = 2
	message.Samples[0].At = policy.ServerTime.Add(time.Second)
	if err = engine.ObserveMessage(message); err != nil {
		t.Fatal(err)
	}
	if engine.Checkpoint().HelperSequence != 2 {
		t.Fatal("helper sequence not persisted")
	}
}

func TestEngineStoresServiceObservationAndRejectsInvalidState(t *testing.T) {
	queue, err := OpenQueue(filepath.Join(t.TempDir(), "services.db"), QueueLimit)
	if err != nil {
		t.Fatal(err)
	}
	defer queue.Close()
	policy := testPolicy()
	engine, err := NewEngine(queue, policy, policy.ServerTime)
	if err != nil {
		t.Fatal(err)
	}
	valid := ServiceObservation{Name: "Spooler", State: "running", StartupType: "automatic", At: policy.ServerTime}
	if err := engine.ObserveService(valid); err != nil {
		t.Fatal(err)
	}
	if engine.Checkpoint().Sequence != 1 || queue.Stats().Events != 1 {
		t.Fatal("service event was not committed with sequence")
	}
	valid.Name = "secret\nservice"
	if engine.ObserveService(valid) == nil {
		t.Fatal("malformed service accepted")
	}
	valid.Name = "Spooler"
	valid.At = policy.ServerTime.Add(24 * time.Hour)
	if engine.ObserveService(valid) == nil {
		t.Fatal("expired policy accepted service collection")
	}
}
