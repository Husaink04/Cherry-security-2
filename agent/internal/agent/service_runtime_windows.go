package agent

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
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
	Endpoint      string                `json:"endpoint"`
	TrustPath     string                `json:"trust_path"`
	DataDirectory string                `json:"data_directory"`
	UserSID       string                `json:"user_sid"`
	ServicePath   string                `json:"service_path"`
	SystemEvents  <-chan SystemBoundary `json:"-"`
}

type SystemBoundary struct {
	State     string
	At        time.Time
	Monotonic time.Duration
	Session   string
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

func policyUsableAt(policy Policy, now time.Time) error {
	if err := ValidatePolicy(policy); err != nil || policy.ServerTime.After(now.Add(2*time.Minute)) || !now.Before(policy.ServerTime.Add(time.Duration(policy.ValidForSeconds)*time.Second)) {
		return errors.New("policy time invalid or expired")
	}
	return nil
}

func selectStartupPolicy(queue *Queue, now time.Time, fetch func() (Policy, error)) (Policy, bool, error) {
	fresh, err := fetch()
	if err == nil {
		if validationError := policyUsableAt(fresh, now); validationError == nil {
			return fresh, false, nil
		} else {
			err = validationError
		}
	}
	if IsCredentialRejected(err) {
		return Policy{}, false, err
	}
	checkpoint, cacheError := queue.LoadCheckpoint()
	if cacheError != nil || policyUsableAt(checkpoint.Policy, now) != nil {
		return Policy{}, false, errors.New("fresh and cached policy unavailable")
	}
	return checkpoint.Policy, true, nil
}

func safeState(sample Sample, policy Policy) string {
	switch sample.State {
	case "active":
		if !policy.Allows(sample.At) {
			return "outside_schedule"
		}
		if sample.LastInputAge >= time.Duration(policy.IdleSeconds)*time.Second {
			return "idle"
		}
		return "collecting"
	case "idle", "locked", "outside_schedule", "suspended", "logged_out", "unsupported_session", "helper_missing":
		return sample.State
	default:
		return "error"
	}
}

func jitteredRetry(base time.Duration, jitter uint32) time.Duration {
	const maximum = 5 * time.Minute
	if base > maximum {
		base = maximum
	}
	delay := base*3/4 + time.Duration(jitter%51)*base/100
	if delay > maximum {
		return maximum
	}
	return delay
}

func randomRetry(base time.Duration) time.Duration {
	var data [4]byte
	if _, err := rand.Read(data[:]); err != nil {
		return jitteredRetry(base, 25)
	}
	return jitteredRetry(base, binary.LittleEndian.Uint32(data[:]))
}

func resetTimer(timer *time.Timer, delay time.Duration) {
	if !timer.Stop() {
		select {
		case <-timer.C:
		default:
		}
	}
	timer.Reset(delay)
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
	now := time.Now().UTC()
	policy, cached, err := selectStartupPolicy(queue, now, func() (Policy, error) {
		return client.Policy(ctx, credential.Token)
	})
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
	state.update(func(status *Status) {
		if cached {
			status.Policy = "cached"
		} else {
			status.Policy = "current"
		}
	})
	started := time.Now()
	var collection struct {
		sync.RWMutex
		enabled   bool
		permanent bool
	}
	collection.enabled = true
	// Service inventory ends with a permanent stop; the helper pipe stays up so the tray can show why.
	servicesContext, stopServices := context.WithCancel(ctx)
	defer stopServices()
	stopCollection := func(collectionState, policyState, lastError string, permanent bool) {
		collection.Lock()
		collection.enabled = false
		collection.permanent = collection.permanent || permanent
		collection.Unlock()
		if permanent {
			stopServices()
		}
		state.update(func(value *Status) {
			value.State = collectionState
			value.Policy = policyState
			value.LastError = lastError
		})
	}
	resumeCollection := func() bool {
		collection.Lock()
		defer collection.Unlock()
		if collection.permanent {
			return false
		}
		collection.enabled = true
		return true
	}
	isPermanent := func() bool {
		collection.RLock()
		defer collection.RUnlock()
		return collection.permanent
	}
	binding := SessionBinding{UserSID: config.UserSID, SessionID: ^uint32(0), ServiceSID: serviceIdentity, ServicePath: config.ServicePath}
	go func() {
		_ = listenHelperPipe(ctx, binding, func(message HelperMessage) (HelperReply, error) {
			checkpoint := engine.Checkpoint()
			if message.Kind == "hello" || message.Kind == "status" {
				state.update(func(value *Status) { value.Helper = "healthy" })
				status := state.get()
				return HelperReply{Policy: &checkpoint.Policy, Status: &status, State: "connected"}, nil
			}
			collection.RLock()
			if !collection.enabled {
				collection.RUnlock()
				status := state.get()
				return HelperReply{Status: &status, State: "stopped"}, nil
			}
			if policyUsableAt(checkpoint.Policy, time.Now().UTC()) != nil {
				collection.RUnlock()
				stopCollection("policy_unavailable", "unavailable", "policy", false)
				status := state.get()
				return HelperReply{Status: &status, State: "stopped"}, nil
			}
			if err := engine.ObserveMessage(message); err != nil {
				collection.RUnlock()
				return HelperReply{}, err
			}
			last := message.Samples[len(message.Samples)-1]
			state.update(func(value *Status) {
				value.State = safeState(last, checkpoint.Policy)
				value.Helper = "healthy"
				value.LastError = "none"
			})
			collection.RUnlock()
			status := state.get()
			return HelperReply{Status: &status, State: "acknowledged"}, nil
		}, func() {
			collection.RLock()
			defer collection.RUnlock()
			if !collection.enabled {
				return
			}
			_ = engine.MarkHelperMissing(time.Now().UTC(), time.Since(started), "console")
			state.update(func(value *Status) {
				value.State = "helper_missing"
				value.Helper = "missing"
				value.LastError = "helper"
			})
		})
	}()
	go func() {
		observe := func(observation ServiceObservation) error {
			collection.RLock()
			defer collection.RUnlock()
			if !collection.enabled {
				return nil
			}
			return engine.ObserveService(observation)
		}
		if observeError := ObserveServices(servicesContext, observe); observeError != nil && servicesContext.Err() == nil {
			state.update(func(value *Status) { value.LastError = "inventory" })
		}
	}()
	policyTicker := time.NewTicker(time.Minute)
	deliveryTimer := time.NewTimer(time.Duration(policy.UploadSeconds) * time.Second)
	heartbeatTicker := time.NewTicker(time.Minute)
	defer policyTicker.Stop()
	defer deliveryTimer.Stop()
	defer heartbeatTicker.Stop()
	retryBase := 2 * time.Second
	for {
		select {
		case <-ctx.Done():
			return nil
		case boundary := <-config.SystemEvents:
			collection.RLock()
			if collection.enabled {
				if boundary.At.IsZero() {
					boundary.At = time.Now().UTC()
				}
				if boundary.Session == "" {
					boundary.Session = "console"
				}
				if boundary.Monotonic == 0 {
					boundary.Monotonic = time.Since(started)
				}
				if boundaryError := engine.MarkSystemBoundary(boundary.At, boundary.Monotonic, boundary.Session, boundary.State); boundaryError == nil {
					state.update(func(value *Status) { value.State = boundary.State })
				}
			}
			collection.RUnlock()
		case <-policyTicker.C:
			if isPermanent() {
				continue
			}
			fresh, policyError := client.Policy(ctx, credential.Token)
			if IsCredentialRejected(policyError) {
				stopCollection("revoked", "unavailable", "credential", true)
				continue
			}
			updateError := policyError
			if updateError == nil {
				updateError = engine.UpdatePolicy(fresh, time.Now().UTC())
			}
			if updateError != nil {
				// A fetched policy that could not be stored is a local storage problem, not a policy one.
				reason := "policy"
				if policyError == nil {
					reason = "storage"
				}
				if policyUsableAt(policy, time.Now().UTC()) != nil {
					stopCollection("policy_unavailable", "unavailable", reason, false)
				} else {
					state.update(func(value *Status) { value.Policy = "cached"; value.LastError = reason })
				}
			} else {
				policy = fresh
				resetTimer(deliveryTimer, time.Duration(policy.UploadSeconds)*time.Second)
				if resumeCollection() {
					state.update(func(value *Status) { value.Policy = "current"; value.LastError = "none" })
				}
			}
		case <-deliveryTimer.C:
			if isPermanent() {
				resetTimer(deliveryTimer, 5*time.Minute)
				continue
			}
			if deliveryError := engine.Deliver(ctx, client, credential.Token); deliveryError != nil {
				if IsCredentialRejected(deliveryError) {
					stopCollection("revoked", "unavailable", "credential", true)
					resetTimer(deliveryTimer, 5*time.Minute)
					continue
				}
				state.update(func(value *Status) { value.LastError = "network" })
				resetTimer(deliveryTimer, randomRetry(retryBase))
				if retryBase < 5*time.Minute {
					retryBase *= 2
					if retryBase > 5*time.Minute {
						retryBase = 5 * time.Minute
					}
				}
			} else {
				retryBase = 2 * time.Second
				resetTimer(deliveryTimer, time.Duration(policy.UploadSeconds)*time.Second)
			}
		case <-heartbeatTicker.C:
			if isPermanent() {
				continue
			}
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
			heartbeatError := client.Heartbeat(ctx, credential.Token, health)
			if IsCredentialRejected(heartbeatError) {
				stopCollection("revoked", "unavailable", "credential", true)
			} else if IsIntegrityRejected(heartbeatError) {
				// The server refuses inconsistent loss counters until an administrator recovers the device.
				state.update(func(value *Status) { value.LastError = "integrity" })
			} else if heartbeatError != nil {
				state.update(func(value *Status) { value.LastError = "network" })
			}
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

// errCollectionStopped means the service declined a sample on purpose (revoked, integrity, or no usable policy).
var errCollectionStopped = errors.New("service stopped collection")

// applyServiceStatus shows a stopped service state to the employee; other states come from the helper's own samples.
func applyServiceStatus(value *Status, reported *Status) {
	if reported == nil || validateStatus(*reported) != nil {
		return
	}
	switch reported.State {
	case "revoked", "error", "policy_unavailable":
		value.State = reported.State
		value.Policy = reported.Policy
		value.LastError = reported.LastError
	}
	value.QueueEvents = reported.QueueEvents
	value.LostEvents = reported.LostEvents
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
					applyServiceStatus(value, reply.Status)
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
					if acknowledgement.Nonce != nonce || acknowledgement.Sequence != message.Sequence {
						return errors.New("invalid service acknowledgement")
					}
					if acknowledgement.State == "stopped" {
						// The sequence is not advanced: the service recorded nothing for this message.
						status.update(func(value *Status) { applyServiceStatus(value, acknowledgement.Status) })
						return errCollectionStopped
					}
					if acknowledgement.State != "acknowledged" {
						return errors.New("invalid service acknowledgement")
					}
					sequence++
					return nil
				}
				if pending != nil {
					err = send(pending)
					if errors.Is(err, errCollectionStopped) {
						pending = nil
					}
					if err != nil {
						connection.Close()
						if errors.Is(err, errCollectionStopped) {
							waitContext(helperContext, time.Minute)
						}
						continue
					}
					pending = nil
				}
				err = ObserveDesktop(helperContext, func(sample Sample) error {
					message := &HelperMessage{Version: 1, Nonce: nonce, Sequence: sequence + 1, MessageID: token(), HelperInstance: instance, Kind: "samples", Samples: []Sample{sample}}
					pending = message
					if sendError := send(message); sendError != nil {
						if errors.Is(sendError, errCollectionStopped) {
							// Collection is off by the service's decision; this sample is intentionally not kept.
							pending = nil
						}
						return sendError
					}
					pending = nil
					status.update(func(value *Status) { value.State = safeState(sample, *reply.Policy) })
					return nil
				})
			}
		}
		connection.Close()
		if errors.Is(err, errCollectionStopped) {
			// Check back once a minute instead of reconnecting after every sample.
			waitContext(helperContext, time.Minute)
		}
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
