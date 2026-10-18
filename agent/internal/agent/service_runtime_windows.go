package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/windows"
)

type Config struct {
	Endpoint      string `json:"endpoint"`
	TrustPath     string `json:"trust_path"`
	DataDirectory string `json:"data_directory"`
	UserSID       string `json:"user_sid"`
	ServicePath   string `json:"service_path"`
}

func (config Config) Validate() error {
	endpoint, err := url.Parse(config.Endpoint)
	if err != nil || endpoint.Scheme != "https" || endpoint.Hostname() == "" || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" || (endpoint.Path != "" && endpoint.Path != "/") {
		return errors.New("invalid HTTPS endpoint")
	}
	for _, path := range []string{config.TrustPath, config.DataDirectory, config.ServicePath} {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path || strings.ContainsAny(path, "\x00\r\n") {
			return errors.New("absolute canonical path required")
		}
	}
	if !strings.EqualFold(filepath.Ext(config.ServicePath), ".exe") {
		return errors.New("service executable required")
	}
	sid, err := windows.StringToSid(config.UserSID)
	if err != nil || sid.String() != config.UserSID || !(strings.HasPrefix(config.UserSID, "S-1-5-21-") || strings.HasPrefix(config.UserSID, "S-1-12-1-")) {
		return errors.New("selected user SID required")
	}
	return nil
}

func LoadConfig(path string) (Config, error) {
	var config Config
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return config, errors.New("absolute config path required")
	}
	file, err := os.Open(path)
	if err != nil {
		return config, err
	}
	defer file.Close()
	decoder := json.NewDecoder(io.LimitReader(file, 64*1024+1))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&config); err != nil {
		return Config{}, errors.New("invalid agent config")
	}
	if decoder.Decode(new(any)) != io.EOF {
		return Config{}, errors.New("multiple config values")
	}
	return config, config.Validate()
}

type runtimeStatus struct {
	mu     sync.RWMutex
	status Status
}

func newRuntimeStatus(state string) *runtimeStatus {
	return &runtimeStatus{status: Status{State: state, Helper: "missing", Policy: "unavailable", LastError: "none"}}
}
func (state *runtimeStatus) get() Status {
	state.mu.RLock()
	defer state.mu.RUnlock()
	return state.status
}
func (state *runtimeStatus) update(change func(*Status)) {
	state.mu.Lock()
	change(&state.status)
	state.mu.Unlock()
}

func readBounded(path string, limit int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || len(data) == 0 || int64(len(data)) > limit {
		return nil, errors.New("invalid bounded file")
	}
	return data, nil
}

func credentialPath(config Config) string {
	return filepath.Join(config.DataDirectory, "credential.dat")
}

func loadCredential(config Config) (Credential, error) {
	var credential Credential
	blob, err := readBounded(credentialPath(config), 16*1024)
	if err != nil {
		return credential, err
	}
	plain, err := UnprotectCredential(blob)
	if err != nil {
		return credential, err
	}
	defer clear(plain)
	decoder := json.NewDecoder(bytes.NewReader(plain))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&credential); err != nil || decoder.Decode(new(any)) != io.EOF || !validToken(credential.Token) || !validToken(credential.DeviceID) {
		return Credential{}, errors.New("invalid protected credential")
	}
	return credential, nil
}

func storeCredential(config Config, credential Credential) error {
	if !validToken(credential.Token) || !validToken(credential.DeviceID) {
		return errors.New("invalid credential")
	}
	plain, err := json.Marshal(credential)
	if err != nil {
		return err
	}
	defer clear(plain)
	blob, err := ProtectCredential(plain)
	if err != nil {
		return err
	}
	path := credentialPath(config)
	if _, err = os.Lstat(path); err == nil {
		return errors.New("credential already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	file, err := os.CreateTemp(config.DataDirectory, "credential-*.new")
	if err != nil {
		return err
	}
	temporary := file.Name()
	saved := false
	defer func() {
		if !saved {
			_ = os.Remove(temporary)
		}
	}()
	if _, err = file.Write(blob); err == nil {
		err = file.Sync()
	}
	closeError := file.Close()
	if err != nil {
		return err
	}
	if closeError != nil {
		return closeError
	}
	if err = os.Rename(temporary, path); err != nil {
		return err
	}
	saved = true
	return nil
}

func waitForEnrollment(ctx context.Context, config Config, client *Client) (Credential, error) {
	if credential, err := loadCredential(config); err == nil {
		return credential, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return Credential{}, err
	}
	hostname, err := os.Hostname()
	if err != nil || hostname == "" || len(hostname) > 253 {
		return Credential{}, errors.New("invalid hostname")
	}
	enrollmentContext, cancel := context.WithCancel(ctx)
	defer cancel()
	result := make(chan Credential, 1)
	failures := make(chan error, 1)
	go func() {
		failures <- ServeEnrollment(enrollmentContext, func(requestContext context.Context, key []byte) error {
			credential, enrollError := client.Enroll(requestContext, Enrollment{Key: string(key), Hostname: hostname, OS: runtime.GOOS + "/" + runtime.GOARCH, Version: "m1", Simulated: false})
			if enrollError != nil {
				return enrollError
			}
			if enrollError = storeCredential(config, credential); enrollError != nil {
				return enrollError
			}
			select {
			case result <- credential:
			default:
			}
			return nil
		})
	}()
	select {
	case credential := <-result:
		return credential, nil
	case err = <-failures:
		return Credential{}, err
	case <-ctx.Done():
		return Credential{}, ctx.Err()
	}
}

func ServiceIdentity() (string, error) {
	sid, _, _, err := windows.LookupSID("", `NT SERVICE\CherrySecurityAgent`)
	if err != nil {
		return "", err
	}
	return sid.String(), nil
}

func safeState(sample Sample) string {
	switch sample.State {
	case "active":
		return "collecting"
	case "idle", "locked", "outside_schedule", "suspended", "logged_out", "unsupported_session", "helper_missing":
		return sample.State
	default:
		return "error"
	}
}

func RunService(ctx context.Context, config Config) error {
	if err := config.Validate(); err != nil {
		return err
	}
	ca, err := readBounded(config.TrustPath, 1024*1024)
	if err != nil {
		return err
	}
	client, err := NewClient(config.Endpoint, ca)
	if err != nil {
		return err
	}
	queue, err := OpenQueue(filepath.Join(config.DataDirectory, "queue.db"), QueueLimit)
	if err != nil {
		return err
	}
	defer queue.Close()
	credential, err := waitForEnrollment(ctx, config, client)
	if err != nil {
		return err
	}
	policy, err := client.Policy(ctx, credential.Token)
	if err != nil {
		if IsCredentialRejected(err) {
			<-ctx.Done()
			return nil
		}
		return err
	}
	engine, err := NewEngine(queue, policy, time.Now().UTC())
	if err != nil {
		return err
	}
	serviceIdentity, err := ServiceIdentity()
	if err != nil {
		return err
	}
	state := newRuntimeStatus("helper_missing")
	state.update(func(status *Status) { status.Policy = "current" })
	started := time.Now()
	collectorContext, cancel := context.WithCancel(ctx)
	defer cancel()
	binding := SessionBinding{UserSID: config.UserSID, SessionID: ^uint32(0), ServiceSID: serviceIdentity, ServicePath: config.ServicePath}
	go func() {
		_ = listenHelperPipe(collectorContext, binding, func(message HelperMessage) (HelperReply, error) {
			checkpoint := engine.Checkpoint()
			if message.Kind == "hello" || message.Kind == "status" {
				state.update(func(value *Status) { value.Helper = "healthy" })
				status := state.get()
				return HelperReply{Policy: &checkpoint.Policy, Status: &status, State: "connected"}, nil
			}
			if err := engine.ObserveMessage(message); err != nil {
				return HelperReply{}, err
			}
			last := message.Samples[len(message.Samples)-1]
			state.update(func(value *Status) { value.State = safeState(last); value.Helper = "healthy"; value.LastError = "none" })
			return HelperReply{State: "acknowledged"}, nil
		}, func() {
			_ = engine.MarkHelperMissing(time.Now().UTC(), time.Since(started), "console")
			state.update(func(value *Status) {
				value.State = "helper_missing"
				value.Helper = "missing"
				value.LastError = "helper"
			})
		})
	}()
	go func() {
		if observeError := ObserveServices(collectorContext, engine.ObserveService); observeError != nil && collectorContext.Err() == nil {
			state.update(func(value *Status) { value.LastError = "inventory" })
		}
	}()
	policyTicker := time.NewTicker(time.Minute)
	deliveryTicker := time.NewTicker(time.Duration(policy.UploadSeconds) * time.Second)
	heartbeatTicker := time.NewTicker(time.Minute)
	defer policyTicker.Stop()
	defer deliveryTicker.Stop()
	defer heartbeatTicker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-policyTicker.C:
			fresh, policyError := client.Policy(ctx, credential.Token)
			if IsCredentialRejected(policyError) {
				cancel()
				state.update(func(value *Status) {
					value.State = "revoked"
					value.Policy = "unavailable"
					value.LastError = "credential"
				})
				<-ctx.Done()
				return nil
			}
			if policyError != nil || engine.UpdatePolicy(fresh, time.Now().UTC()) != nil {
				state.update(func(value *Status) { value.Policy = "unavailable"; value.LastError = "policy" })
			} else {
				policy = fresh
				deliveryTicker.Reset(time.Duration(policy.UploadSeconds) * time.Second)
				state.update(func(value *Status) { value.Policy = "current"; value.LastError = "none" })
			}
		case <-deliveryTicker.C:
			if deliveryError := engine.Deliver(ctx, client, credential.Token); deliveryError != nil {
				if IsCredentialRejected(deliveryError) {
					cancel()
					state.update(func(value *Status) { value.State = "revoked"; value.LastError = "credential" })
					<-ctx.Done()
					return nil
				}
				state.update(func(value *Status) { value.LastError = "network" })
			}
		case <-heartbeatTicker.C:
			stats := queue.Stats()
			current := state.get()
			age := int(time.Since(policy.ServerTime).Seconds())
			if age < 0 {
				age = 0
			}
			if age > 86400 {
				age = 86400
			}
			health := Heartbeat{Version: 2, Helper: current.Helper, Extension: "missing", State: current.State, PolicyVersion: policy.PolicyVersion, PolicyAgeSeconds: age, QueueEvents: stats.Events, QueueBytes: stats.Bytes, LostEvents: stats.LostEvents, LossEpoch: stats.Epoch, LastError: current.LastError}
			_ = client.Heartbeat(ctx, credential.Token, health)
			state.update(func(value *Status) { value.QueueEvents = stats.Events; value.LostEvents = stats.LostEvents })
		}
	}
}

func CurrentSessionBinding(config Config) (SessionBinding, error) {
	identity := windows.GetCurrentProcessToken()
	user, err := identity.GetTokenUser()
	if err != nil || user.User.Sid.String() != config.UserSID {
		return SessionBinding{}, errors.New("helper must run as selected user")
	}
	session, err := tokenSession(identity)
	if err != nil || session != windows.WTSGetActiveConsoleSessionId() {
		return SessionBinding{}, errors.New("helper requires active console session")
	}
	serviceIdentity, err := ServiceIdentity()
	if err != nil {
		return SessionBinding{}, err
	}
	return SessionBinding{UserSID: config.UserSID, SessionID: session, ServiceSID: serviceIdentity, ServicePath: config.ServicePath}, nil
}

func RunHelper(ctx context.Context, binding SessionBinding) error {
	helperContext, cancel := context.WithCancel(ctx)
	defer cancel()
	status := newRuntimeStatus("offline")
	statusReady := make(chan error, 1)
	statusResult := make(chan error, 1)
	go func() {
		statusResult <- runStatus(helperContext, status.get, statusReady)
		cancel()
	}()
	if err := <-statusReady; err != nil {
		return err
	}
	instance := token()
	var sequence uint64
	var pending *HelperMessage
	for {
		connection, err := ConnectHelperPipe(helperContext, binding)
		if err != nil {
			status.update(func(value *Status) { value.State = "offline"; value.Helper = "missing"; value.LastError = "network" })
			if !waitContext(helperContext, 2*time.Second) {
				select {
				case statusError := <-statusResult:
					if errors.Is(statusError, context.Canceled) {
						return nil
					}
					return statusError
				default:
					return nil
				}
			}
			continue
		}
		connection.SetDeadline(time.Now().Add(10 * time.Second))
		if err = WriteFrame(connection, HelperMessage{Version: 1, Kind: "hello"}); err == nil {
			var reply HelperReply
			err = ReadFrame(connection, &reply)
			if err == nil && reply.Version == 1 && validToken(reply.Nonce) && reply.Policy != nil && ValidatePolicy(*reply.Policy) == nil {
				status.update(func(value *Status) {
					value.State = "collecting"
					value.Helper = "healthy"
					value.Policy = "current"
					value.LastError = "none"
				})
				nonce := reply.Nonce
				send := func(message *HelperMessage) error {
					message.Nonce = nonce
					connection.SetDeadline(time.Now().Add(10 * time.Second))
					if writeError := WriteFrame(connection, *message); writeError != nil {
						return writeError
					}
					var acknowledgement HelperReply
					if readError := ReadFrame(connection, &acknowledgement); readError != nil {
						return readError
					}
					if acknowledgement.Nonce != nonce || acknowledgement.Sequence != message.Sequence || acknowledgement.State != "acknowledged" {
						return errors.New("invalid service acknowledgement")
					}
					sequence++
					return nil
				}
				if pending != nil {
					err = send(pending)
					if err != nil {
						connection.Close()
						continue
					}
					pending = nil
				}
				err = ObserveDesktop(helperContext, func(sample Sample) error {
					message := &HelperMessage{Version: 1, Nonce: nonce, Sequence: sequence + 1, MessageID: token(), HelperInstance: instance, Kind: "samples", Samples: []Sample{sample}}
					pending = message
					if sendError := send(message); sendError != nil {
						return sendError
					}
					pending = nil
					status.update(func(value *Status) { value.State = safeState(sample) })
					return nil
				})
			}
		}
		connection.Close()
		if helperContext.Err() != nil {
			select {
			case statusError := <-statusResult:
				if errors.Is(statusError, context.Canceled) {
					return nil
				}
				return statusError
			default:
				return nil
			}
		}
		if !waitContext(helperContext, 2*time.Second) {
			return nil
		}
	}
}

func waitContext(ctx context.Context, duration time.Duration) bool {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}
