package agent

import (
	"encoding/json"
	"testing"
	"time"
)

func TestTimelineIdleScheduleAndRecovery(t *testing.T) {
	policy := testPolicy()
	timeline := NewTimeline(policy)
	start := policy.ServerTime
	var events []Event
	for second := 0; second <= 360; second++ {
		part, err := timeline.Observe(Sample{At: start.Add(time.Duration(second) * time.Second), Monotonic: time.Duration(second) * time.Second, LastInputAge: time.Duration(second) * time.Second, App: "editor.exe", State: "active", Session: "local-1"})
		if err != nil {
			t.Fatal(err)
		}
		events = append(events, part...)
	}
	var idle time.Duration
	for _, event := range events {
		if event.Kind == "application" {
			t.Fatal("no-input interval was incorrectly finalized active")
		}
		if event.Kind == "idle" {
			idle += event.Payload.End.Sub(event.Payload.Start)
		}
	}
	if idle != 60*time.Second {
		t.Fatalf("idle finalized %s, want 60s trailing window", idle)
	}
	checkpoint := timeline.Checkpoint()
	raw, _ := json.Marshal(checkpoint)
	var persisted Checkpoint
	if err := json.Unmarshal(raw, &persisted); err != nil {
		t.Fatal(err)
	}
	restored, err := RestoreTimeline(persisted, start.Add(365*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	more, err := restored.Observe(Sample{At: start.Add(366 * time.Second), LastInputAge: 0, App: "editor.exe", State: "active", Session: "local-1"})
	if err != nil {
		t.Fatal(err)
	}
	for _, event := range more {
		if event.Kind == "application" && event.Payload.Start.Before(start.Add(366*time.Second)) {
			t.Fatal("restart fabricated activity")
		}
	}
}

func TestSuspendBoundarySurvivesLongResumeGap(t *testing.T) {
	policy := testPolicy()
	timeline := NewTimeline(policy)
	session := "console"
	if _, err := timeline.Observe(Sample{At: policy.ServerTime, Monotonic: 0, State: "active", App: "editor.exe", Session: session}); err != nil {
		t.Fatal(err)
	}
	if _, err := timeline.Observe(Sample{At: policy.ServerTime.Add(time.Second), Monotonic: time.Second, State: "suspended", Session: session}); err != nil {
		t.Fatal(err)
	}
	events, err := timeline.Observe(Sample{At: policy.ServerTime.Add(time.Hour), Monotonic: 2 * time.Second, State: "active", App: "editor.exe", Session: session})
	if err != nil {
		t.Fatal(err)
	}
	if len(events) == 0 || events[len(events)-1].Kind != "gap" || events[len(events)-1].Payload.GapReason != "suspended" {
		t.Fatalf("suspend boundary lost across resume: %+v", events)
	}
}

func TestPolicyChangeDoesNotBroadenProvisionalCollection(t *testing.T) {
	policy := testPolicy()
	policy.Schedule = Schedule{Days: []int{6}, Start: "09:00", End: "09:01"}
	timeline := NewTimeline(policy)
	start := policy.ServerTime
	var events []Event
	for second := 0; second <= 90; second++ {
		part, err := timeline.Observe(Sample{At: start.Add(time.Duration(second) * time.Second), Monotonic: time.Duration(second) * time.Second, App: "one.exe", State: "active", Session: "local"})
		if err != nil {
			t.Fatal(err)
		}
		events = append(events, part...)
	}
	changed := testPolicy()
	changed.PolicyVersion = "policy-2"
	flushed, err := timeline.ApplyPolicy(changed, start.Add(90*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	events = append(events, flushed...)
	var duration time.Duration
	for _, event := range events {
		duration += event.Payload.End.Sub(event.Payload.Start)
		if event.Payload.End.After(start.Add(time.Minute)) {
			t.Fatal("new policy broadened past collection")
		}
	}
	if duration != time.Minute {
		t.Fatalf("duration %s want 60s", duration)
	}
}

func TestClockAndSessionBoundaries(t *testing.T) {
	policy := testPolicy()
	timeline := NewTimeline(policy)
	start := policy.ServerTime
	samples := []Sample{
		{At: start, Monotonic: 0, State: "active", App: "a.exe", Session: "one"},
		{At: start.Add(time.Second), Monotonic: time.Second, State: "active", App: "b.exe", Session: "one"},
		{At: start.Add(2 * time.Second), Monotonic: 2 * time.Second, State: "locked", Session: "one"},
		{At: start.Add(3 * time.Second), Monotonic: 3 * time.Second, State: "unsupported_session", Session: "two"},
		{At: start.Add(20 * time.Second), Monotonic: 4 * time.Second, State: "active", App: "b.exe", Session: "one"},
	}
	var events []Event
	for _, sample := range samples {
		part, err := timeline.Observe(sample)
		if err != nil {
			t.Fatal(err)
		}
		events = append(events, part...)
	}
	part, err := timeline.ApplyPolicy(policy, start.Add(20*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	events = append(events, part...)
	for i, event := range events {
		if !event.Payload.End.After(event.Payload.Start) {
			t.Fatal("nonpositive interval")
		}
		if i > 0 && event.Payload.Start.Before(events[i-1].Payload.End) {
			t.Fatal("overlapping intervals")
		}
	}
	if _, err = timeline.Observe(Sample{At: start, State: "active", App: "b.exe", Session: "one"}); err == nil {
		t.Fatal("backward clock accepted")
	}
	if _, err = timeline.Observe(Sample{At: start.Add(21 * time.Second), State: "active", App: "C:\\secret\\app.exe", Session: "one"}); err == nil {
		t.Fatal("path accepted")
	}
}

func TestPolicyBoundaryAfterLastSampleDoesNotInventActivity(t *testing.T) {
	policy := testPolicy()
	timeline := NewTimeline(policy)
	start := policy.ServerTime
	if _, err := timeline.Observe(Sample{At: start, State: "active", App: "one.exe", Session: "local"}); err != nil {
		t.Fatal(err)
	}
	changed := policy
	changed.PolicyVersion = "next"
	first, err := timeline.ApplyPolicy(changed, start.Add(10*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	second, err := timeline.Observe(Sample{At: start.Add(11 * time.Second), State: "active", App: "two.exe", Session: "local"})
	if err != nil {
		t.Fatal(err)
	}
	for _, event := range append(first, second...) {
		if event.Kind == "application" {
			t.Fatalf("invented application activity across policy boundary: %+v", event)
		}
	}
}

func TestSessionAndClockChangesRotateTelemetryEpoch(t *testing.T) {
	policy := testPolicy()
	timeline := NewTimeline(policy)
	start := policy.ServerTime
	original := timeline.Checkpoint().Session
	samples := []Sample{{At: start, Monotonic: 0, State: "active", App: "one.exe", Session: "first"}, {At: start.Add(time.Second), Monotonic: time.Second, State: "active", App: "one.exe", Session: "first"}, {At: start.Add(2 * time.Second), Monotonic: 2 * time.Second, State: "active", App: "two.exe", Session: "second"}}
	for _, sample := range samples {
		if _, err := timeline.Observe(sample); err != nil {
			t.Fatal(err)
		}
	}
	afterSession := timeline.Checkpoint().Session
	if afterSession == original {
		t.Fatal("session change retained telemetry epoch")
	}
	if _, err := timeline.Observe(Sample{At: start.Add(20 * time.Second), Monotonic: 3 * time.Second, State: "active", App: "two.exe", Session: "second"}); err != nil {
		t.Fatal(err)
	}
	if timeline.Checkpoint().Session == afterSession {
		t.Fatal("clock discontinuity retained telemetry epoch")
	}
}
