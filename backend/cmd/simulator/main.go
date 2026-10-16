// Simulator sends deterministic fixtures only; it never observes the host operating system.
package main

import (
	"bytes"
	"cherrysecurity/internal/app"
	"encoding/json"
	"flag"
	"fmt"
	"golang.org/x/term"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type state struct {
	DeviceID string      `json:"device_id"`
	Token    string      `json:"device_token"`
	Session  string      `json:"session_id"`
	Start    time.Time   `json:"start"`
	Events   []app.Event `json:"events"`
}

func post(client *http.Client, url, token string, value any, out any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	req, err := http.NewRequest("POST", url, bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	response, err := client.Do(req)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode >= 300 {
		return fmt.Errorf("API rejected request with status %d; inspect input or credential state", response.StatusCode)
	}
	if out != nil {
		return json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(out)
	}
	return nil
}
func main() {
	url := flag.String("url", "http://web:8080", "API origin accessible from inside the Compose network")
	path := flag.String("state", "/state/simulator-state.json", "private persistent simulator state file")
	flag.Parse()
	if !strings.HasPrefix(*url, "http://web:") && !strings.HasPrefix(*url, "http://127.0.0.1:") && !strings.HasPrefix(*url, "https://") {
		log.Fatal("use the private Compose web host, loopback, or verified HTTPS")
	}
	client := &http.Client{Timeout: 20 * time.Second}
	var saved state
	data, err := os.ReadFile(*path)
	if err == nil {
		info, statErr := os.Stat(*path)
		if statErr != nil || info.Mode().Perm()&0077 != 0 {
			log.Fatal("state file must be readable only by its owner")
		}
		if err = json.Unmarshal(data, &saved); err != nil {
			log.Fatal("invalid simulator state")
		}
	} else if !os.IsNotExist(err) {
		log.Fatal("unable to read simulator state")
	}
	if saved.Token == "" {
		if !term.IsTerminal(int(os.Stdin.Fd())) {
			log.Fatal("first enrollment requires a terminal; never pass enrollment keys in command arguments")
		}
		fmt.Print("Enrollment key (hidden): ")
		key, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Println()
		if err != nil {
			log.Fatal("key input failed")
		}
		input := map[string]any{"enrollment_key": strings.TrimSpace(string(key)), "hostname": "SIMULATED-WINDOWS-M0", "os": "Windows simulated fixture", "agent_version": "m0-simulator", "simulated": true}
		if err = post(client, *url+"/api/agent/enroll", "", input, &saved); err != nil {
			log.Fatal(err)
		}
		saved.Session = app.RandomToken()
		saved.Start = time.Now().UTC().Add(-time.Hour).Truncate(time.Minute)
		fixture := func(id, kind string, sequence int64, offset, duration int, p app.Payload) app.Event {
			if kind != "service" {
				p.Start = saved.Start.Add(time.Duration(offset) * time.Second)
				p.End = p.Start.Add(time.Duration(duration) * time.Second)
			}
			return app.Event{ID: saved.Session + "-" + id, Session: saved.Session, Sequence: sequence, Observed: saved.Start.Add(time.Duration(offset+duration) * time.Second), Kind: kind, Payload: p}
		}
		saved.Events = []app.Event{
			fixture("chrome", "application", 1, 0, 600, app.Payload{App: "chrome.exe"}),
			fixture("docs", "browser", 2, 0, 300, app.Payload{Hostname: "docs.example.com"}),
			fixture("editor", "application", 3, 600, 300, app.Payload{App: "Code.exe"}),
			fixture("idle", "idle", 4, 900, 120, app.Payload{}),
			fixture("service", "service", 5, 1020, 0, app.Payload{Service: "Spooler", State: "running", StartupType: "automatic"}),
		}
		if err = os.MkdirAll(filepath.Dir(*path), 0700); err != nil {
			log.Fatal("cannot create state directory")
		}
		encoded, _ := json.MarshalIndent(saved, "", "  ")
		file, err := os.OpenFile(*path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			log.Fatal("cannot safely create state file; do not reuse consumed key")
		}
		_, writeErr := file.Write(encoded)
		syncErr := file.Sync()
		closeErr := file.Close()
		if writeErr != nil || syncErr != nil || closeErr != nil {
			log.Fatal("cannot persist device credentials; obtain a replacement enrollment key")
		}
	}
	if err = post(client, *url+"/api/agent/heartbeat", saved.Token, map[string]any{"helper": "simulated", "extension": "simulated"}, nil); err != nil {
		log.Fatal(err)
	}
	if err = post(client, *url+"/api/agent/events", saved.Token, map[string]any{"schema_version": 1, "events": saved.Events}, nil); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("SIMULATED device %s uploaded/replayed safely. Fixture starts %s UTC. Expected application=900s, browser=300s (subset), idle=120s.\n", saved.DeviceID, saved.Start.Format(time.RFC3339))
}
