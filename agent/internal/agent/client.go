package agent

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type Client struct {
	base string
	http *http.Client
}
type HTTPError struct{ Status int }

func (err *HTTPError) Error() string { return "agent API rejected request" }
func IsCredentialRejected(err error) bool {
	var failure *HTTPError
	return errors.As(err, &failure) && failure.Status == 401
}

func NewClient(baseURL string, caPEM []byte) (*Client, error) {
	parsed, err := url.Parse(baseURL)
	if err != nil || parsed.Scheme != "https" || parsed.Hostname() == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || (parsed.Path != "" && parsed.Path != "/") {
		return nil, errors.New("HTTPS origin required")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("valid scoped CA required")
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}
	transport.MaxIdleConnsPerHost = 2
	return &Client{base: strings.TrimRight(baseURL, "/"), http: &http.Client{Transport: transport, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}
func (client *Client) request(ctx context.Context, method, path, credential string, input, output any) error {
	if credential != "" && (len(credential) != 64 || strings.ContainsAny(credential, "\r\n")) {
		return errors.New("invalid credential format")
	}
	var encoded []byte
	var err error
	if input != nil {
		encoded, err = json.Marshal(input)
		if err != nil {
			return err
		}
		if len(encoded) > MaxBatchBytes {
			return errors.New("request exceeds byte limit")
		}
	}
	request, err := http.NewRequestWithContext(ctx, method, client.base+path, bytes.NewReader(encoded))
	if err != nil {
		return errors.New("invalid request")
	}
	request.Header.Set("Content-Type", "application/json")
	if credential != "" {
		request.Header.Set("Authorization", "Bearer "+credential)
	}
	response, err := client.http.Do(request)
	if err != nil {
		return errors.New("TLS or network request failed")
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return &HTTPError{Status: response.StatusCode}
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, MaxBatchBytes+1))
	if err != nil || len(raw) > MaxBatchBytes {
		return errors.New("invalid response size")
	}
	if output == nil {
		return nil
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(output); err != nil {
		return errors.New("invalid response schema")
	}
	if decoder.Decode(new(any)) != io.EOF {
		return errors.New("multiple response values")
	}
	return nil
}
func (client *Client) Policy(ctx context.Context, credential string) (Policy, error) {
	var policy Policy
	if err := client.request(ctx, "GET", "/api/agent/policy", credential, nil, &policy); err != nil {
		return policy, err
	}
	return policy, ValidatePolicy(policy)
}
func (client *Client) Upload(ctx context.Context, credential string, events []Event) (Acknowledgement, error) {
	var ack Acknowledgement
	if len(events) < 1 || len(events) > MaxBatchEvents {
		return ack, errors.New("invalid event count")
	}
	err := client.request(ctx, "POST", "/api/agent/events", credential, struct {
		Version int     `json:"schema_version"`
		Events  []Event `json:"events"`
	}{2, events}, &ack)
	if err != nil {
		return ack, err
	}
	if len(ack.IDs) != len(events) {
		return ack, errors.New("incomplete acknowledgement")
	}
	expected := map[string]bool{}
	for _, event := range events {
		if expected[event.ID] {
			return ack, errors.New("duplicate submitted event")
		}
		expected[event.ID] = true
	}
	for _, id := range ack.IDs {
		if !expected[id] {
			return ack, errors.New("invalid acknowledgement IDs")
		}
		delete(expected, id)
	}
	return ack, nil
}
func (client *Client) Heartbeat(ctx context.Context, credential string, health Heartbeat) error {
	var result struct {
		Status string `json:"status"`
	}
	if err := client.request(ctx, "POST", "/api/agent/heartbeat", credential, health, &result); err != nil {
		return err
	}
	if result.Status != "accepted" {
		return errors.New("heartbeat not accepted")
	}
	return nil
}

type Enrollment struct {
	Key       string `json:"enrollment_key"`
	Hostname  string `json:"hostname"`
	OS        string `json:"os"`
	Version   string `json:"agent_version"`
	Simulated bool   `json:"simulated"`
}
type Credential struct {
	DeviceID string `json:"device_id"`
	Token    string `json:"device_token"`
}

func (client *Client) Enroll(ctx context.Context, input Enrollment) (Credential, error) {
	var result Credential
	if err := client.request(ctx, "POST", "/api/agent/enroll", "", input, &result); err != nil {
		return result, err
	}
	if len(result.DeviceID) != 64 || len(result.Token) != 64 {
		return Credential{}, errors.New("invalid enrollment response")
	}
	return result, nil
}
