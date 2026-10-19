package agent

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
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

func TestStartupUsesStillValidCachedPolicyWhenRefreshFails(t *testing.T) {
	queue, err := OpenQueue(filepath.Join(t.TempDir(), "queue.db"), 1024*1024)
	if err != nil {
		t.Fatal(err)
	}
	defer queue.Close()
	policy := testPolicy()
	if err = queue.CommitObservation(token(), NewTimeline(policy).Checkpoint(), nil); err != nil {
		t.Fatal(err)
	}
	selected, cached, err := selectStartupPolicy(queue, policy.ServerTime.Add(time.Minute), func() (Policy, error) { return Policy{}, errors.New("offline") })
	if err != nil || !cached || selected.PolicyVersion != policy.PolicyVersion {
		t.Fatalf("valid cached policy not selected: cached=%v policy=%+v err=%v", cached, selected, err)
	}
	if _, _, err = selectStartupPolicy(queue, policy.ServerTime.Add(25*time.Hour), func() (Policy, error) { return Policy{}, errors.New("offline") }); err == nil {
		t.Fatal("expired cached policy accepted")
	}
}

func TestStatusAndRetryBounds(t *testing.T) {
	policy := testPolicy()
	sample := Sample{At: policy.ServerTime, State: "active", LastInputAge: time.Duration(policy.IdleSeconds) * time.Second}
	if state := safeState(sample, policy); state != "idle" {
		t.Fatalf("idle sample reported as %q", state)
	}
	policy.Schedule = Schedule{Days: []int{int(policy.ServerTime.Weekday())}, Start: "00:00", End: "00:01"}
	sample.LastInputAge = 0
	sample.At = policy.ServerTime.Add(12 * time.Hour)
	if state := safeState(sample, policy); state != "outside_schedule" {
		t.Fatalf("out-of-schedule sample reported as %q", state)
	}
	for _, base := range []time.Duration{2 * time.Second, 5 * time.Minute} {
		delay := jitteredRetry(base, 0)
		if delay < base*3/4 || delay > base*5/4 || delay > 5*time.Minute {
			t.Fatalf("retry delay out of bounds: base=%v delay=%v", base, delay)
		}
	}
}

func TestHelperShowsStoppedServiceStatus(t *testing.T) {
	connected := func() Status {
		return Status{State: "collecting", Helper: "healthy", Policy: "current", LastError: "none"}
	}
	// A revoked service must never be shown to the employee as collecting.
	value := connected()
	applyServiceStatus(&value, &Status{State: "revoked", Helper: "healthy", Policy: "unavailable", LastError: "credential", QueueEvents: 3})
	if value.State != "revoked" || value.Policy != "unavailable" || value.LastError != "credential" || value.QueueEvents != 3 {
		t.Fatalf("stopped status not shown: %+v", value)
	}
	// The service's pre-sample "helper_missing" is stale once this helper is connected.
	value = connected()
	applyServiceStatus(&value, &Status{State: "helper_missing", Helper: "healthy", Policy: "current", LastError: "none"})
	if value.State != "collecting" {
		t.Fatalf("connected helper shown as %q", value.State)
	}
	// Unvalidated or missing status leaves the helper's own view untouched.
	value = connected()
	applyServiceStatus(&value, &Status{State: "revoked", Helper: "bogus", Policy: "current", LastError: "none"})
	applyServiceStatus(&value, nil)
	if value != connected() {
		t.Fatalf("invalid status changed the tray: %+v", value)
	}
}
