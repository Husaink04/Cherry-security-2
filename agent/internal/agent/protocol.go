package agent

import "time"

const (
	QueueLimit     = 50 * 1024 * 1024
	MaxBatchBytes  = 768 * 1024
	MaxBatchEvents = 500
)

type Schedule struct {
	Days         []int  `json:"days"`
	Start        string `json:"start"`
	End          string `json:"end"`
	Unrestricted bool   `json:"unrestricted"`
}
type Policy struct {
	Version          int       `json:"schema_version"`
	PolicyVersion    string    `json:"policy_version"`
	ServerTime       time.Time `json:"server_time"`
	Timezone         string    `json:"timezone"`
	IdleSeconds      int       `json:"idle_seconds"`
	Schedule         Schedule  `json:"collection_schedule"`
	RawRetentionDays int       `json:"raw_retention_days"`
	IngestNotBefore  time.Time `json:"ingest_not_before"`
	UploadSeconds    int       `json:"upload_seconds"`
	ValidForSeconds  int       `json:"valid_for_seconds"`
}
type Payload struct {
	GapReason   string    `json:"gap_reason,omitempty"`
	Start       time.Time `json:"start,omitempty"`
	End         time.Time `json:"end,omitempty"`
	App         string    `json:"app,omitempty"`
	Hostname    string    `json:"hostname,omitempty"`
	Service     string    `json:"service,omitempty"`
	State       string    `json:"state,omitempty"`
	StartupType string    `json:"startup_type,omitempty"`
}
type Event struct {
	ID       string    `json:"event_id"`
	Session  string    `json:"session_id"`
	Sequence int64     `json:"sequence"`
	Observed time.Time `json:"observed_at"`
	Kind     string    `json:"kind"`
	Payload  Payload   `json:"payload"`
}
type Heartbeat struct {
	Version          int    `json:"schema_version"`
	Helper           string `json:"helper"`
	Extension        string `json:"extension"`
	State            string `json:"collection_state"`
	PolicyVersion    string `json:"policy_version"`
	PolicyAgeSeconds int    `json:"policy_age_seconds"`
	QueueEvents      int64  `json:"queue_events"`
	QueueBytes       int64  `json:"queue_bytes"`
	LostEvents       int64  `json:"lost_events"`
	LossEpoch        string `json:"loss_epoch"`
	LastError        string `json:"last_error"`
}
type Acknowledgement struct {
	IDs []string `json:"accepted_event_ids"`
}
type ServiceObservation struct {
	Name        string
	State       string
	StartupType string
	At          time.Time
}
