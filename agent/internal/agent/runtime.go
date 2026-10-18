package agent

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"sync"
	"time"
)

type Engine struct {
	mu       sync.Mutex
	queue    *Queue
	timeline *Timeline
}

func NewEngine(queue *Queue, policy Policy, now time.Time) (*Engine, error) {
	if queue == nil {
		return nil, errors.New("queue required")
	}
	if err := ValidatePolicy(policy); err != nil {
		return nil, err
	}
	if policy.ServerTime.After(now.Add(2*time.Minute)) || !now.Before(policy.ServerTime.Add(time.Duration(policy.ValidForSeconds)*time.Second)) {
		return nil, errors.New("policy time invalid or expired")
	}
	checkpoint, err := queue.LoadCheckpoint()
	if err == sql.ErrNoRows {
		return &Engine{queue: queue, timeline: NewTimeline(policy)}, nil
	}
	if err != nil {
		return nil, err
	}
	timeline, err := RestoreTimeline(checkpoint, now)
	if err != nil {
		return nil, err
	}
	engine := &Engine{queue: queue, timeline: timeline}
	if checkpoint.Policy.PolicyVersion != policy.PolicyVersion {
		if err = engine.UpdatePolicy(policy, now); err != nil {
			return nil, err
		}
	}
	return engine, nil
}

func (engine *Engine) Checkpoint() Checkpoint {
	engine.mu.Lock()
	defer engine.mu.Unlock()
	return engine.timeline.Checkpoint()
}

func (engine *Engine) ObserveMessage(message HelperMessage) error {
	engine.mu.Lock()
	defer engine.mu.Unlock()
	if message.Version != 1 || message.Kind != "samples" || !validToken(message.Nonce) || !validToken(message.MessageID) || !validToken(message.HelperInstance) || message.Sequence == 0 || len(message.Samples) < 1 || len(message.Samples) > 5 {
		return errors.New("invalid helper observation")
	}
	digest, err := observationDigest(message)
	if err != nil {
		return err
	}
	seen, err := engine.queue.SeenMessage(message.MessageID, digest)
	if err != nil {
		return err
	}
	if seen {
		return nil
	}
	checkpoint := engine.timeline.Checkpoint()
	if checkpoint.HelperInstance == message.HelperInstance {
		if message.Sequence != checkpoint.HelperSequence+1 {
			return errors.New("stale or skipped helper sequence")
		}
	} else if message.Sequence != 1 {
		return errors.New("new helper sequence must start at one")
	}
	candidate := &Timeline{checkpoint: checkpoint, restored: engine.timeline.restored}
	helperChanged := checkpoint.HelperInstance != "" && checkpoint.HelperInstance != message.HelperInstance
	if helperChanged && checkpoint.Last != nil {
		candidate.restored = true
	}
	events := []Event{}
	for _, sample := range message.Samples {
		part, err := candidate.Observe(sample)
		if err != nil {
			return err
		}
		events = append(events, part...)
	}
	if helperChanged {
		candidate.checkpoint.Session = token()
		candidate.checkpoint.Sequence = 0
	}
	candidate.checkpoint.HelperInstance = message.HelperInstance
	candidate.checkpoint.HelperSequence = message.Sequence
	if err = engine.queue.CommitMessage(message.MessageID, digest, candidate.Checkpoint(), events); err != nil {
		return err
	}
	engine.timeline = candidate
	return nil
}

func (engine *Engine) UpdatePolicy(policy Policy, at time.Time) error {
	engine.mu.Lock()
	defer engine.mu.Unlock()
	if err := ValidatePolicy(policy); err != nil {
		return err
	}
	if policy.ServerTime.After(at.Add(2*time.Minute)) || !at.Before(policy.ServerTime.Add(time.Duration(policy.ValidForSeconds)*time.Second)) {
		return errors.New("policy time invalid or expired")
	}
	candidate := &Timeline{checkpoint: engine.timeline.Checkpoint(), restored: engine.timeline.restored}
	events, err := candidate.ApplyPolicy(policy, at)
	if err != nil {
		return err
	}
	if err = engine.queue.CommitObservation(token(), candidate.Checkpoint(), events); err != nil {
		return err
	}
	engine.timeline = candidate
	return nil
}

func (engine *Engine) ObserveService(observation ServiceObservation) error {
	engine.mu.Lock()
	defer engine.mu.Unlock()
	if observation.Name == "" || len(observation.Name) > 120 || strings.ContainsAny(observation.Name, "\x00\r\n") || observation.At.IsZero() {
		return errors.New("invalid service observation")
	}
	switch observation.State {
	case "running", "stopped", "paused", "start_pending", "stop_pending", "continue_pending", "pause_pending", "unknown", "removed":
	default:
		return errors.New("invalid service state")
	}
	switch observation.StartupType {
	case "automatic", "manual", "disabled", "unknown":
	default:
		return errors.New("invalid service startup type")
	}
	policy := engine.timeline.checkpoint.Policy
	if observation.At.Before(policy.ServerTime.Add(-5*time.Minute)) || !observation.At.Before(policy.ServerTime.Add(time.Duration(policy.ValidForSeconds)*time.Second)) {
		return errors.New("policy unavailable or expired")
	}
	checkpoint := engine.timeline.Checkpoint()
	event := Event{ID: token(), Session: checkpoint.Session, Sequence: checkpoint.Sequence, Observed: observation.At.UTC(), Kind: "service", Payload: Payload{Service: observation.Name, State: observation.State, StartupType: observation.StartupType}}
	checkpoint.Sequence++
	if err := engine.queue.CommitObservation(token(), checkpoint, []Event{event}); err != nil {
		return err
	}
	engine.timeline.checkpoint = checkpoint
	return nil
}

func (engine *Engine) MarkHelperMissing(at time.Time, monotonic time.Duration, session string) error {
	engine.mu.Lock()
	defer engine.mu.Unlock()
	if at.IsZero() || monotonic < 0 || session == "" || len(session) > 128 {
		return errors.New("invalid helper loss boundary")
	}
	policy := engine.timeline.checkpoint.Policy
	if !at.Before(policy.ServerTime.Add(time.Duration(policy.ValidForSeconds) * time.Second)) {
		return errors.New("policy unavailable or expired")
	}
	candidate := &Timeline{checkpoint: engine.timeline.Checkpoint(), restored: engine.timeline.restored}
	events, err := candidate.Observe(Sample{At: at, Monotonic: monotonic, State: "helper_missing", Session: session})
	if err != nil {
		return err
	}
	if err = engine.queue.CommitObservation(token(), candidate.Checkpoint(), events); err != nil {
		return err
	}
	engine.timeline = candidate
	return nil
}

func (engine *Engine) Deliver(ctx context.Context, client *Client, credential string) error {
	engine.mu.Lock()
	watermark := engine.timeline.checkpoint.Policy.IngestNotBefore
	engine.mu.Unlock()
	if !watermark.IsZero() {
		for {
			if err := ctx.Err(); err != nil {
				return err
			}
			dropped, err := engine.queue.DropBefore(watermark)
			if err != nil {
				return err
			}
			if dropped == 0 {
				break
			}
		}
	}
	return DeliverOnce(ctx, engine.queue, client, credential)
}
