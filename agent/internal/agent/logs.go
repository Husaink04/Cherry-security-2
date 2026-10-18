package agent

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const MaxLogFileBytes = 2560 * 1024

type Log struct {
	mu    sync.Mutex
	path  string
	limit int64
}

func OpenLog(path string, limit int64) (*Log, error) {
	if !filepath.IsAbs(path) || limit < 4096 || limit > MaxLogFileBytes {
		return nil, errors.New("invalid log path or budget")
	}
	return &Log{path: path, limit: limit}, nil
}

func (log *Log) Write(code string, count int) error {
	switch code {
	case "network", "tls", "auth", "storage", "ipc", "policy", "collector", "service", "unavailable", "integrity":
	default:
		return errors.New("invalid operational code")
	}
	if count < 0 {
		return errors.New("invalid operational count")
	}
	data, err := json.Marshal(struct {
		At    time.Time `json:"at"`
		Code  string    `json:"code"`
		Count int       `json:"count"`
	}{time.Now().UTC(), code, count})
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if int64(len(data)) > log.limit {
		return errors.New("log record exceeds budget")
	}
	log.mu.Lock()
	defer log.mu.Unlock()
	active, err := os.Lstat(log.path)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	if err == nil && !active.Mode().IsRegular() {
		return errors.New("log path is not regular")
	}
	if active != nil && active.Size() > log.limit {
		return errors.New("log exceeds budget")
	}
	rotated, err := os.Lstat(log.path + ".1")
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	if err == nil && !rotated.Mode().IsRegular() {
		return errors.New("rotated log path is not regular")
	}
	if rotated != nil && rotated.Size() > log.limit {
		return errors.New("rotated log exceeds budget")
	}
	if active != nil && active.Size()+int64(len(data)) > log.limit {
		if rotated != nil {
			if err = os.Remove(log.path + ".1"); err != nil {
				return err
			}
		}
		if err = os.Rename(log.path, log.path+".1"); err != nil {
			return err
		}
	}
	file, err := os.OpenFile(log.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	written, writeErr := file.Write(data)
	closeErr := file.Close()
	if writeErr != nil {
		return writeErr
	}
	if written != len(data) {
		return io.ErrShortWrite
	}
	return closeErr
}
