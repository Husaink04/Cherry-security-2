package agent

import (
	"testing"
	"time"
)

func TestInventoryReconcileAfterMissedChangeAndRecreate(t *testing.T) {
	start := time.Date(2026, 10, 17, 8, 0, 0, 0, time.UTC)
	previous := map[string]ServiceObservation{
		"alpha": {Name: "alpha", State: "running", StartupType: "automatic", At: start},
		"beta":  {Name: "beta", State: "running", StartupType: "manual", At: start},
	}
	current := map[string]ServiceObservation{
		"alpha": {Name: "alpha", State: "stopped", StartupType: "manual", At: start.Add(5 * time.Minute)},
	}
	changes := reconcileInventory(previous, current, start.Add(5*time.Minute), false)
	if len(changes) != 2 || changes[0].Name != "alpha" || changes[0].State != "stopped" || changes[1].Name != "beta" || changes[1].State != "removed" {
		t.Fatalf("missed changes: %+v", changes)
	}
	refresh := reconcileInventory(current, current, start.Add(24*time.Hour), true)
	if len(refresh) != 1 || refresh[0].Name != "alpha" {
		t.Fatalf("daily refresh: %+v", refresh)
	}
}
