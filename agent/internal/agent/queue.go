package agent

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

type QueueStats struct {
	Events, Bytes, LostEvents int64
	Epoch, Error              string
}
type Queue struct {
	mu         sync.Mutex
	deliveryMu sync.Mutex
	db         *sql.DB
	path       string
	limit      int64
}

func OpenQueue(path string, limitBytes int64) (*Queue, error) {
	if !filepath.IsAbs(path) || limitBytes < 1024*1024 || limitBytes > QueueLimit {
		return nil, errors.New("invalid queue path or budget")
	}
	if info, err := os.Lstat(path); err == nil && !info.Mode().IsRegular() {
		return nil, errors.New("queue must be a regular file")
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	fail := func(err error) (*Queue, error) { db.Close(); return nil, err }
	// Reserve room for a worst-case rollback journal, not merely its retained size.
	pages := limitBytes * 2 / 5 / 4096
	for _, statement := range []string{"PRAGMA page_size=4096", "PRAGMA journal_mode=DELETE", "PRAGMA synchronous=FULL", "PRAGMA cache_size=-1024", "PRAGMA busy_timeout=2000", fmt.Sprintf("PRAGMA max_page_count=%d", pages),
		`CREATE TABLE IF NOT EXISTS events(position INTEGER PRIMARY KEY AUTOINCREMENT,id TEXT NOT NULL UNIQUE,payload BLOB NOT NULL,bytes INTEGER NOT NULL,leased INTEGER NOT NULL DEFAULT 0)`,
		`CREATE TABLE IF NOT EXISTS checkpoint(id INTEGER PRIMARY KEY CHECK(id=1),payload BLOB NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS receipts(position INTEGER PRIMARY KEY AUTOINCREMENT,id TEXT NOT NULL UNIQUE,digest TEXT NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS losses(id INTEGER PRIMARY KEY CHECK(id=1),epoch TEXT NOT NULL,count INTEGER NOT NULL)`} {
		if _, err = db.Exec(statement); err != nil {
			return fail(err)
		}
	}
	if _, err = db.Exec("INSERT OR IGNORE INTO losses(id,epoch,count) VALUES(1,?,0)", token()); err != nil {
		return fail(err)
	}
	var pageSize, maxPages int64
	var journal string
	if err = db.QueryRow("PRAGMA page_size").Scan(&pageSize); err != nil {
		return fail(err)
	}
	if err = db.QueryRow("PRAGMA max_page_count").Scan(&maxPages); err != nil {
		return fail(err)
	}
	if err = db.QueryRow("PRAGMA journal_mode").Scan(&journal); err != nil {
		return fail(err)
	}
	if pageSize != 4096 || maxPages > pages || journal != "delete" {
		return fail(errors.New("SQLite limits not applied"))
	}
	return &Queue{db: db, path: path, limit: limitBytes}, nil
}

func (queue *Queue) CommitObservation(messageID string, checkpoint Checkpoint, events []Event) error {
	return queue.commitObservation(messageID, "", checkpoint, events)
}

// CommitMessage uses a stable digest of the helper request so reconnects can be checked before timeline mutation.
func (queue *Queue) CommitMessage(messageID, requestDigest string, checkpoint Checkpoint, events []Event) error {
	if len(requestDigest) != 64 {
		return errors.New("invalid helper digest")
	}
	return queue.commitObservation(messageID, requestDigest, checkpoint, events)
}

func (queue *Queue) SeenMessage(messageID, requestDigest string) (bool, error) {
	queue.mu.Lock()
	defer queue.mu.Unlock()
	if len(messageID) < 1 || len(messageID) > 192 || len(requestDigest) != 64 {
		return false, errors.New("invalid helper message identity")
	}
	var saved string
	err := queue.db.QueryRow("SELECT digest FROM receipts WHERE id=?", messageID).Scan(&saved)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if saved != requestDigest {
		return false, errors.New("conflicting helper replay")
	}
	return true, nil
}

func (queue *Queue) commitObservation(messageID, requestDigest string, checkpoint Checkpoint, events []Event) error {
	queue.mu.Lock()
	defer queue.mu.Unlock()
	if len(messageID) < 1 || len(messageID) > 192 || len(events) > MaxBatchEvents {
		return errors.New("invalid observation bounds")
	}
	checkpointData, err := json.Marshal(checkpoint)
	if err != nil {
		return err
	}
	if len(checkpointData) > 128*1024 {
		return errors.New("checkpoint too large")
	}
	var incoming int64
	encoded := make([][]byte, len(events))
	for i, event := range events {
		data, err := json.Marshal(event)
		if err != nil {
			return err
		}
		if event.ID == "" || len(data) > 4096 {
			return errors.New("event exceeds queue bounds")
		}
		encoded[i] = data
		incoming += int64(len(data))
	}
	digestInput := sha256.New()
	digestInput.Write(checkpointData)
	for _, data := range encoded {
		digestInput.Write(data)
	}
	digest := hex.EncodeToString(digestInput.Sum(nil))
	if requestDigest != "" {
		digest = requestDigest
	}
	tx, err := queue.db.BeginTx(context.Background(), nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var priorDigest string
	err = tx.QueryRow("SELECT digest FROM receipts WHERE id=?", messageID).Scan(&priorDigest)
	if err == nil {
		if priorDigest != digest {
			return errors.New("conflicting observation replay")
		}
		return nil
	}
	if err != sql.ErrNoRows {
		return err
	}
	// Conservative payload admission leaves space for indexes, receipts, and checkpoint.
	capacity := queue.limit/10 - int64(len(checkpointData)) - 4096
	if incoming > capacity {
		return errors.New("observation exceeds queue admission budget")
	}
	var used int64
	if err = tx.QueryRow("SELECT coalesce(sum(bytes),0) FROM events").Scan(&used); err != nil {
		return err
	}
	var lost int64
	type gapRecord struct {
		position int64
		event    Event
		data     []byte
	}
	gaps := []gapRecord{}
	var gapBytes int64
	for used+incoming+gapBytes > capacity {
		var position, size int64
		var raw []byte
		err = tx.QueryRow("SELECT position,bytes,payload FROM events WHERE leased=0 ORDER BY position LIMIT 1").Scan(&position, &size, &raw)
		if err == sql.ErrNoRows {
			return errors.New("queue full with in-flight events")
		}
		if err != nil {
			return err
		}
		var discarded Event
		if err = json.Unmarshal(raw, &discarded); err != nil {
			return errors.New("corrupt queued event")
		}
		if _, err = tx.Exec("DELETE FROM events WHERE position=?", position); err != nil {
			return err
		}
		used -= size
		if discarded.Kind != "gap" {
			lost++
		}
		if discarded.Kind == "application" || discarded.Kind == "idle" || discarded.Kind == "locked" || discarded.Kind == "gap" {
			merged := false
			if len(gaps) > 0 {
				last := &gaps[len(gaps)-1]
				if last.event.Session == discarded.Session && last.event.Payload.End.Equal(discarded.Payload.Start) {
					gapBytes -= int64(len(last.data))
					last.event.Payload.End = discarded.Payload.End
					last.event.Observed = discarded.Observed
					last.data, err = json.Marshal(last.event)
					if err != nil {
						return err
					}
					gapBytes += int64(len(last.data))
					merged = true
				}
			}
			if !merged {
				gap := Event{ID: token(), Session: discarded.Session, Sequence: discarded.Sequence, Observed: discarded.Observed, Kind: "gap", Payload: Payload{Start: discarded.Payload.Start, End: discarded.Payload.End, GapReason: "queue_overflow"}}
				data, err := json.Marshal(gap)
				if err != nil {
					return err
				}
				gaps = append(gaps, gapRecord{position: position, event: gap, data: data})
				gapBytes += int64(len(data))
			}
		}
	}
	for _, gap := range gaps {
		if _, err = tx.Exec("INSERT INTO events(position,id,payload,bytes) VALUES(?,?,?,?)", gap.position, gap.event.ID, gap.data, len(gap.data)); err != nil {
			return err
		}
	}
	for i, event := range events {
		if _, err = tx.Exec("INSERT INTO events(id,payload,bytes) VALUES(?,?,?)", event.ID, encoded[i], len(encoded[i])); err != nil {
			return err
		}
	}
	if _, err = tx.Exec("INSERT INTO checkpoint(id,payload) VALUES(1,?) ON CONFLICT(id) DO UPDATE SET payload=excluded.payload", checkpointData); err != nil {
		return err
	}
	if _, err = tx.Exec("INSERT INTO receipts(id,digest) VALUES(?,?)", messageID, digest); err != nil {
		return err
	}
	if _, err = tx.Exec("DELETE FROM receipts WHERE position <= (SELECT coalesce(max(position),0)-128 FROM receipts)"); err != nil {
		return err
	}
	if _, err = tx.Exec("UPDATE losses SET count=count+? WHERE id=1", lost); err != nil {
		return err
	}
	bytes, err := queue.diskBytes()
	if err != nil || bytes > queue.limit {
		return errors.New("queue disk budget exceeded")
	}
	return tx.Commit()
}

func (queue *Queue) Batch(maxEvents, maxBytes int) ([]Event, error) {
	queue.mu.Lock()
	defer queue.mu.Unlock()
	if maxEvents < 1 || maxEvents > MaxBatchEvents || maxBytes < 1 || maxBytes > MaxBatchBytes {
		return nil, errors.New("invalid batch limit")
	}
	tx, err := queue.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	rows, err := tx.Query("SELECT payload FROM events ORDER BY position LIMIT ?", maxEvents)
	if err != nil {
		return nil, err
	}
	result := []Event{}
	size := 64
	for rows.Next() {
		var raw []byte
		if err = rows.Scan(&raw); err != nil {
			rows.Close()
			return nil, err
		}
		if size+len(raw)+1 > maxBytes {
			break
		}
		var event Event
		if err = json.Unmarshal(raw, &event); err != nil {
			rows.Close()
			return nil, errors.New("corrupt queued event")
		}
		result = append(result, event)
		size += len(raw) + 1
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	for _, event := range result {
		if _, err = tx.Exec("UPDATE events SET leased=1 WHERE id=?", event.ID); err != nil {
			return nil, err
		}
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return result, nil
}

func (queue *Queue) Acknowledge(submitted []Event, ids []string) error {
	queue.mu.Lock()
	defer queue.mu.Unlock()
	if len(ids) != len(submitted) || len(ids) == 0 {
		return errors.New("incomplete acknowledgement")
	}
	expected := map[string]bool{}
	for _, event := range submitted {
		if expected[event.ID] {
			return errors.New("duplicate submitted ID")
		}
		expected[event.ID] = true
	}
	for _, id := range ids {
		if !expected[id] {
			return errors.New("unknown or duplicate acknowledgement ID")
		}
		delete(expected, id)
	}
	tx, err := queue.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, id := range ids {
		result, err := tx.Exec("DELETE FROM events WHERE id=? AND leased=1", id)
		if err != nil {
			return err
		}
		count, err := result.RowsAffected()
		if err != nil || count != 1 {
			return errors.New("acknowledgement no longer matches in-flight event")
		}
	}
	return tx.Commit()
}

func (queue *Queue) DiscardRejected(event Event) error {
	queue.mu.Lock()
	defer queue.mu.Unlock()
	encoded, err := json.Marshal(event)
	if err != nil {
		return err
	}
	tx, err := queue.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var stored []byte
	var leased int
	if err = tx.QueryRow("SELECT payload,leased FROM events WHERE id=?", event.ID).Scan(&stored, &leased); err != nil {
		return err
	}
	if leased != 1 || !bytes.Equal(stored, encoded) {
		return errors.New("rejected event no longer matches in-flight record")
	}
	if _, err = tx.Exec("DELETE FROM events WHERE id=?", event.ID); err != nil {
		return err
	}
	if _, err = tx.Exec("UPDATE losses SET count=count+1 WHERE id=1"); err != nil {
		return err
	}
	return tx.Commit()
}

func (queue *Queue) DropBefore(watermark time.Time) (int, error) {
	if watermark.IsZero() {
		return 0, errors.New("retention watermark required")
	}
	queue.deliveryMu.Lock()
	defer queue.deliveryMu.Unlock()
	queue.mu.Lock()
	defer queue.mu.Unlock()
	tx, err := queue.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	rows, err := tx.Query("SELECT id,payload FROM events ORDER BY position")
	if err != nil {
		return 0, err
	}
	ids := []string{}
	for rows.Next() {
		var id string
		var raw []byte
		if err = rows.Scan(&id, &raw); err != nil {
			rows.Close()
			return 0, err
		}
		var event Event
		if err = json.Unmarshal(raw, &event); err != nil {
			rows.Close()
			return 0, errors.New("corrupt queued event")
		}
		if event.Observed.Before(watermark) || (!event.Payload.Start.IsZero() && event.Payload.Start.Before(watermark)) {
			ids = append(ids, id)
		}
		if len(ids) == 64 {
			break
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return 0, err
	}
	for _, id := range ids {
		if _, err = tx.Exec("DELETE FROM events WHERE id=?", id); err != nil {
			return 0, err
		}
	}
	if _, err = tx.Exec("UPDATE losses SET count=count+? WHERE id=1", len(ids)); err != nil {
		return 0, err
	}
	if err = tx.Commit(); err != nil {
		return 0, err
	}
	return len(ids), nil
}
func (queue *Queue) Stats() QueueStats {
	queue.mu.Lock()
	defer queue.mu.Unlock()
	var stats QueueStats
	if err := queue.db.QueryRow("SELECT count(*) FROM events").Scan(&stats.Events); err != nil {
		stats.Error = "storage"
	}
	if err := queue.db.QueryRow("SELECT epoch,count FROM losses WHERE id=1").Scan(&stats.Epoch, &stats.LostEvents); err != nil {
		stats.Error = "storage"
	}
	bytes, err := queue.diskBytes()
	stats.Bytes = bytes
	if err != nil {
		stats.Error = "storage"
	}
	if stats.Bytes > queue.limit {
		stats.Error = "storage"
	}
	return stats
}

func (queue *Queue) diskBytes() (int64, error) {
	var total int64
	for _, suffix := range []string{"", "-journal", "-wal", "-shm"} {
		info, err := os.Stat(queue.path + suffix)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return 0, err
		}
		total += info.Size()
	}
	return total, nil
}
func (queue *Queue) LoadCheckpoint() (Checkpoint, error) {
	queue.mu.Lock()
	defer queue.mu.Unlock()
	var data []byte
	if err := queue.db.QueryRow("SELECT payload FROM checkpoint WHERE id=1").Scan(&data); err != nil {
		return Checkpoint{}, err
	}
	return decodeCheckpoint(data)
}
func (queue *Queue) Close() error {
	queue.deliveryMu.Lock()
	defer queue.deliveryMu.Unlock()
	queue.mu.Lock()
	defer queue.mu.Unlock()
	return queue.db.Close()
}
