package agent

import (
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"testing"
	"time"
)

func fixtureEvent(number int) Event {
	start := time.Date(2026, 10, 17, 9, 0, 0, 0, time.UTC).Add(time.Duration(number) * time.Minute)
	return Event{ID: token(), Session: "fixture", Sequence: int64(number), Observed: start.Add(time.Minute), Kind: "application", Payload: Payload{Start: start, End: start.Add(time.Minute), App: "editor.exe"}}
}

func TestQueueHelperReplyLostAcrossReconnect(t *testing.T) {
	path := filepath.Join(t.TempDir(), "replay.db")
	queue, err := OpenQueue(path, QueueLimit)
	if err != nil {
		t.Fatal(err)
	}
	checkpoint := NewTimeline(testPolicy()).Checkpoint()
	event := fixtureEvent(0)
	hash := sha256.Sum256([]byte("stable helper sample"))
	digest := hex.EncodeToString(hash[:])
	if err = queue.CommitMessage("helper:1", digest, checkpoint, []Event{event}); err != nil {
		t.Fatal(err)
	}
	if err = queue.Close(); err != nil {
		t.Fatal(err)
	}
	queue, err = OpenQueue(path, QueueLimit)
	if err != nil {
		t.Fatal(err)
	}
	defer queue.Close()
	seen, err := queue.SeenMessage("helper:1", digest)
	if err != nil || !seen {
		t.Fatalf("durable helper receipt missing: %v %v", seen, err)
	}
	other := sha256.Sum256([]byte("changed helper sample"))
	if _, err = queue.SeenMessage("helper:1", hex.EncodeToString(other[:])); err == nil {
		t.Fatal("changed replay accepted")
	}
	if queue.Stats().Events != 1 {
		t.Fatal("helper replay changed queued event count")
	}
}

func TestQueueDropsOnlyEventsBeforeRetentionWatermark(t *testing.T) {
	queue, err := OpenQueue(filepath.Join(t.TempDir(), "retention.db"), QueueLimit)
	if err != nil {
		t.Fatal(err)
	}
	defer queue.Close()
	events := []Event{fixtureEvent(0), fixtureEvent(1), fixtureEvent(2)}
	if err = queue.CommitObservation("retention", NewTimeline(testPolicy()).Checkpoint(), events); err != nil {
		t.Fatal(err)
	}
	dropped, err := queue.DropBefore(events[1].Payload.Start.Add(30 * time.Second))
	if err != nil || dropped != 2 {
		t.Fatalf("retention discard: %d %v", dropped, err)
	}
	stats := queue.Stats()
	if stats.Events != 1 || stats.LostEvents != 2 {
		t.Fatalf("wrong retention accounting: %+v", stats)
	}
}
func TestQueueDurableAcknowledgementAndReplay(t *testing.T) {
	path := filepath.Join(t.TempDir(), "queue.db")
	queue, err := OpenQueue(path, QueueLimit)
	if err != nil {
		t.Fatal(err)
	}
	event := fixtureEvent(0)
	checkpoint := NewTimeline(testPolicy()).Checkpoint()
	if err = queue.CommitObservation("session:1", checkpoint, []Event{event}); err != nil {
		t.Fatal(err)
	}
	if err = queue.Close(); err != nil {
		t.Fatal(err)
	}
	queue, err = OpenQueue(path, QueueLimit)
	if err != nil {
		t.Fatal(err)
	}
	defer queue.Close()
	if err = queue.CommitObservation("session:1", checkpoint, []Event{event}); err != nil {
		t.Fatal(err)
	}
	changed := event
	changed.Payload.App = "other.exe"
	if err = queue.CommitObservation("session:1", checkpoint, []Event{changed}); err == nil {
		t.Fatal("conflicting replay accepted")
	}
	batch, err := queue.Batch(500, MaxBatchBytes)
	if err != nil || len(batch) != 1 || batch[0].ID != event.ID {
		t.Fatalf("replay %v %v", batch, err)
	}
	if queue.Acknowledge(batch, []string{"unknown"}) == nil || queue.Acknowledge(batch, nil) == nil || queue.Acknowledge(batch, []string{event.ID, event.ID}) == nil {
		t.Fatal("invalid acknowledgement accepted")
	}
	if queue.Stats().Events != 1 {
		t.Fatal("invalid acknowledgement removed data")
	}
	if err = queue.Acknowledge(batch, []string{event.ID}); err != nil {
		t.Fatal(err)
	}
	if err = queue.CommitObservation("session:1", checkpoint, []Event{event}); err != nil {
		t.Fatal(err)
	}
	if queue.Stats().Events != 0 {
		t.Fatal("acknowledged local replay recreated event")
	}
}

func TestQueueFullAndJournalBudget(t *testing.T) {
	limit := int64(1024 * 1024)
	queue, err := OpenQueue(filepath.Join(t.TempDir(), "small.db"), limit)
	if err != nil {
		t.Fatal(err)
	}
	defer queue.Close()
	checkpoint := NewTimeline(testPolicy()).Checkpoint()
	for i := 0; i < 1500; i++ {
		if err = queue.CommitObservation(token(), checkpoint, []Event{fixtureEvent(i)}); err != nil {
			t.Fatalf("observation %d failed: %v; stats=%+v", i, err, queue.Stats())
		}
		if queue.Stats().Bytes > limit {
			t.Fatal("queue file budget exceeded")
		}
	}
	stats := queue.Stats()
	if stats.LostEvents == 0 || stats.Events == 0 || stats.Epoch == "" {
		t.Fatalf("missing loss accounting: %+v", stats)
	}
	batch, err := queue.Batch(2, MaxBatchBytes)
	if err != nil || len(batch) > 2 {
		t.Fatal("batch count unbounded")
	}
}

func TestQueueOverflowCoverageAndInFlightLease(t *testing.T) {
	queue, err := OpenQueue(filepath.Join(t.TempDir(), "lease.db"), 1024*1024)
	if err != nil {
		t.Fatal(err)
	}
	defer queue.Close()
	checkpoint := NewTimeline(testPolicy()).Checkpoint()
	first := fixtureEvent(0)
	if err = queue.CommitObservation("first", checkpoint, []Event{first}); err != nil {
		t.Fatal(err)
	}
	leased, err := queue.Batch(1, MaxBatchBytes)
	if err != nil {
		t.Fatal(err)
	}
	for i := 1; i < 750; i++ {
		if err = queue.CommitObservation(token(), checkpoint, []Event{fixtureEvent(i)}); err != nil {
			t.Fatalf("observation %d failed: %v; stats=%+v", i, err, queue.Stats())
		}
	}
	batch, err := queue.Batch(500, MaxBatchBytes)
	if err != nil {
		t.Fatal(err)
	}
	foundFirst, foundGap := false, false
	for _, event := range batch {
		if event.ID == first.ID {
			foundFirst = true
		}
		if event.Kind == "gap" && event.Payload.GapReason == "queue_overflow" {
			foundGap = true
		}
	}
	if !foundFirst || !foundGap {
		t.Fatalf("in-flight event preserved=%v overflow gap=%v", foundFirst, foundGap)
	}
	for i, left := range batch {
		for _, right := range batch[i+1:] {
			if left.Payload.Start.Before(right.Payload.End) && right.Payload.Start.Before(left.Payload.End) {
				t.Fatalf("overlapping queued coverage: %+v %+v", left, right)
			}
		}
	}
	if err = queue.Acknowledge(leased, []string{first.ID}); err != nil {
		t.Fatal(err)
	}
}
