package agent

import (
	"context"
	"errors"
)

// DeliverOnce preserves uncertain batches and drops at most one isolated, server-rejected record.
func DeliverOnce(ctx context.Context, queue *Queue, client *Client, credential string) error {
	if queue == nil || client == nil {
		return errors.New("delivery dependencies required")
	}
	queue.deliveryMu.Lock()
	defer queue.deliveryMu.Unlock()
	batch, err := queue.Batch(MaxBatchEvents, MaxBatchBytes)
	if err != nil || len(batch) == 0 {
		return err
	}
	rejected := 0
	return deliverGroup(ctx, queue, client, credential, batch, &rejected)
}

func deliverGroup(ctx context.Context, queue *Queue, client *Client, credential string, events []Event, rejected *int) error {
	ack, err := client.Upload(ctx, credential, events)
	if err == nil {
		return queue.Acknowledge(events, ack.IDs)
	}
	var failure *HTTPError
	if !errors.As(err, &failure) || (failure.Status != 400 && failure.Status != 422) {
		return err
	}
	if len(events) == 1 {
		if *rejected >= 1 {
			return errors.New("multiple validation failures; delivery paused")
		}
		if err = queue.DiscardRejected(events[0]); err != nil {
			return err
		}
		*rejected = *rejected + 1
		return nil
	}
	middle := len(events) / 2
	if err = deliverGroup(ctx, queue, client, credential, events[:middle], rejected); err != nil {
		return err
	}
	return deliverGroup(ctx, queue, client, credential, events[middle:], rejected)
}
