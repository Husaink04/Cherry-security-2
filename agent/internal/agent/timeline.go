package agent

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

type Sample struct {
	At           time.Time
	Monotonic    time.Duration
	LastInputAge time.Duration
	App          string
	State        string
	Session      string
}
type interval struct {
	Start, End        time.Time
	Kind, App, Reason string
}
type Checkpoint struct {
	Policy         Policy
	Last           *Sample
	Pending        []interval
	Session        string
	Sequence       int64
	Finalized      time.Time
	HelperInstance string
	HelperSequence uint64
}
type Timeline struct {
	checkpoint Checkpoint
	restored   bool
}

func token() string {
	var data [32]byte
	if _, err := rand.Read(data[:]); err != nil {
		panic("OS randomness unavailable")
	}
	return hex.EncodeToString(data[:])
}
func NewTimeline(policy Policy) *Timeline {
	return &Timeline{checkpoint: Checkpoint{Policy: policy, Session: token()}}
}
func (timeline *Timeline) Checkpoint() Checkpoint {
	snapshot := timeline.checkpoint
	snapshot.Pending = append([]interval(nil), snapshot.Pending...)
	snapshot.Policy.Schedule.Days = append([]int(nil), snapshot.Policy.Schedule.Days...)
	if snapshot.Last != nil {
		last := *snapshot.Last
		snapshot.Last = &last
	}
	return snapshot
}
func RestoreTimeline(checkpoint Checkpoint, now time.Time) (*Timeline, error) {
	if err := ValidatePolicy(checkpoint.Policy); err != nil {
		return nil, err
	}
	if len(checkpoint.Pending) > 4096 || checkpoint.Sequence < 0 || checkpoint.Session == "" || checkpoint.Finalized.After(now) || (checkpoint.HelperInstance == "" && checkpoint.HelperSequence != 0) || len(checkpoint.HelperInstance) > 64 {
		return nil, errors.New("invalid checkpoint or backward clock")
	}
	previous := checkpoint.Finalized
	for _, pending := range checkpoint.Pending {
		if !pending.End.After(pending.Start) || pending.Start.Before(previous) || pending.End.After(now) {
			return nil, errors.New("invalid checkpoint intervals")
		}
		previous = pending.End
	}
	timeline := &Timeline{checkpoint: checkpoint, restored: true}
	timeline.checkpoint = timeline.Checkpoint()
	return timeline, nil
}

func (timeline *Timeline) Observe(sample Sample) ([]Event, error) {
	if err := ValidatePolicy(timeline.checkpoint.Policy); err != nil {
		return nil, err
	}
	if sample.At.IsZero() || sample.LastInputAge < 0 || sample.LastInputAge > 24*time.Hour || len(sample.Session) > 128 || len(sample.App) > 120 || strings.ContainsAny(sample.App, "\\/:\x00\r\n") {
		return nil, errors.New("invalid observation")
	}
	switch sample.State {
	case "active", "locked", "suspended", "logged_out", "unsupported_session", "helper_missing", "process_unavailable":
	default:
		return nil, errors.New("invalid observation state")
	}
	sample.At = sample.At.UTC().Truncate(time.Second)
	checkpoint := &timeline.checkpoint
	if sample.At.Before(checkpoint.Finalized) || (checkpoint.Last != nil && sample.At.Before(checkpoint.Last.At)) {
		return nil, errors.New("backward clock")
	}
	if checkpoint.Last == nil {
		checkpoint.Last = &sample
		return nil, nil
	}
	previous := *checkpoint.Last
	if timeline.restored {
		for index := range checkpoint.Pending {
			if checkpoint.Pending[index].Kind == "application" {
				checkpoint.Pending[index].Kind = "gap"
				checkpoint.Pending[index].App = ""
				checkpoint.Pending[index].Reason = "helper_missing"
			}
		}
	}
	if sample.At.Equal(previous.At) {
		checkpoint.Last = &sample
		return nil, nil
	}
	period := interval{Start: previous.At, End: sample.At, Kind: "application", App: previous.App}
	delta := sample.At.Sub(previous.At)
	drift := delta - (sample.Monotonic - previous.Monotonic)
	switch {
	case timeline.restored:
		period.Kind = "gap"
		period.Reason = "helper_missing"
	case sample.Session != previous.Session:
		period.Kind = "gap"
		period.Reason = "unsupported_session"
	case previous.State == "locked":
		period.Kind = "locked"
	case previous.State != "active":
		period.Kind = "gap"
		period.Reason = previous.State
	case drift > 2*time.Second || drift < -2*time.Second:
		period.Kind = "gap"
		period.Reason = "clock_discontinuity"
	case delta > 5*time.Second:
		period.Kind = "gap"
		period.Reason = "helper_missing"
	case previous.App == "":
		period.Kind = "gap"
		period.Reason = "process_unavailable"
	}
	if period.Kind != "application" {
		period.App = ""
	}
	timeline.appendScheduled(period)
	threshold := time.Duration(checkpoint.Policy.IdleSeconds) * time.Second
	if sample.State == "active" && sample.LastInputAge >= threshold && !timeline.restored {
		idleStart := sample.At.Add(-sample.LastInputAge)
		reclassified := make([]interval, 0, len(checkpoint.Pending)+1)
		for _, pending := range checkpoint.Pending {
			if pending.Kind != "application" || !pending.End.After(idleStart) {
				reclassified = append(reclassified, pending)
				continue
			}
			if pending.Start.Before(idleStart) {
				active := pending
				active.End = idleStart
				reclassified = append(reclassified, active)
				pending.Start = idleStart
			}
			pending.Kind = "idle"
			pending.App = ""
			reclassified = append(reclassified, pending)
		}
		checkpoint.Pending = reclassified
	}
	checkpoint.Last = &sample
	timeline.restored = false
	cutoff := sample.At.Add(-threshold)
	if sample.State != "active" || previous.State != "active" || sample.Session != previous.Session || period.Kind == "gap" {
		cutoff = sample.At
	}
	events := timeline.finalize(cutoff, sample.At)
	if len(checkpoint.Pending) > 4096 {
		return events, errors.New("provisional interval limit reached")
	}
	if sample.Session != previous.Session || period.Reason == "clock_discontinuity" {
		checkpoint.Session = token()
		checkpoint.Sequence = 0
	}
	return events, nil
}

func (timeline *Timeline) appendScheduled(period interval) {
	policy := timeline.checkpoint.Policy
	for period.Start.Before(period.End) {
		end := period.Start.Truncate(time.Minute).Add(time.Minute)
		if end.After(period.End) {
			end = period.End
		}
		segment := period
		segment.End = end
		if policy.Allows(segment.Start) && segment.Start.Before(policy.ServerTime.Add(time.Duration(policy.ValidForSeconds)*time.Second)) {
			expiry := policy.ServerTime.Add(time.Duration(policy.ValidForSeconds) * time.Second)
			if segment.End.After(expiry) {
				segment.End = expiry
			}
			pending := timeline.checkpoint.Pending
			if len(pending) > 0 {
				last := &pending[len(pending)-1]
				if last.End.Equal(segment.Start) && last.Kind == segment.Kind && last.App == segment.App && last.Reason == segment.Reason {
					last.End = segment.End
					timeline.checkpoint.Pending = pending
					period.Start = end
					continue
				}
			}
			timeline.checkpoint.Pending = append(pending, segment)
		}
		period.Start = end
	}
}

func (timeline *Timeline) finalize(cutoff, observed time.Time) []Event {
	checkpoint := &timeline.checkpoint
	events := []Event{}
	remaining := []interval{}
	for _, period := range checkpoint.Pending {
		end := period.End
		if end.After(cutoff) {
			end = cutoff
		}
		for period.Start.Before(end) {
			stop := period.Start.Add(time.Minute)
			if stop.After(end) {
				stop = end
			}
			event := Event{ID: token(), Session: checkpoint.Session, Sequence: checkpoint.Sequence, Observed: observed, Kind: period.Kind, Payload: Payload{Start: period.Start, End: stop, App: period.App, GapReason: period.Reason}}
			events = append(events, event)
			checkpoint.Sequence++
			checkpoint.Finalized = stop
			period.Start = stop
		}
		if period.Start.Before(period.End) {
			remaining = append(remaining, period)
		}
	}
	checkpoint.Pending = remaining
	return events
}

func (timeline *Timeline) ApplyPolicy(policy Policy, at time.Time) ([]Event, error) {
	if err := ValidatePolicy(policy); err != nil {
		return nil, err
	}
	if timeline.checkpoint.Last != nil && at.Before(timeline.checkpoint.Last.At) {
		return nil, errors.New("policy boundary precedes observation")
	}
	if previous := timeline.checkpoint.Last; previous != nil && at.After(previous.At) {
		timeline.appendScheduled(interval{Start: previous.At, End: at, Kind: "gap", Reason: "helper_missing"})
		missing := *previous
		missing.At = at
		missing.State = "helper_missing"
		missing.App = ""
		timeline.checkpoint.Last = &missing
	}
	events := timeline.finalize(at, at)
	timeline.checkpoint.Policy = policy
	return events, nil
}

func decodeCheckpoint(data []byte) (Checkpoint, error) {
	var result Checkpoint
	err := json.Unmarshal(data, &result)
	return result, err
}
