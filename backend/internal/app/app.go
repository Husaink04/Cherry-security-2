package app

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Config struct {
	Origin         string
	SecureCookies  bool
	RequestTimeout time.Duration
}
type App struct {
	db          *pgxpool.Pool
	config      Config
	loginLimits sync.Map
}
type principal struct{ ID, Role, OrganizationID, CSRF string }
type apiError struct {
	status  int
	message string
}

func (e *apiError) Error() string  { return e.message }
func invalid(message string) error { return &apiError{400, message} }
func forbidden() error             { return &apiError{403, "access denied"} }
func missing() error               { return &apiError{404, "record not found"} }

type endpoint func(http.ResponseWriter, *http.Request) error

func RandomToken() string {
	data := make([]byte, 32)
	if _, err := rand.Read(data); err != nil {
		panic("secure randomness unavailable")
	}
	return hex.EncodeToString(data)
}
func digest(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}
func send(w http.ResponseWriter, status int, value any) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	return json.NewEncoder(w).Encode(value)
}
func decode(w http.ResponseWriter, r *http.Request, value any) error {
	if strings.Split(r.Header.Get("Content-Type"), ";")[0] != "application/json" {
		return &apiError{415, "application/json required"}
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if err := d.Decode(value); err != nil {
		var max *http.MaxBytesError
		if errors.As(err, &max) {
			return &apiError{413, "request too large"}
		}
		return invalid("invalid JSON or unsupported fields")
	}
	if err := d.Decode(&struct{}{}); err != io.EOF {
		return invalid("one JSON object required")
	}
	return nil
}
func New(db *pgxpool.Pool, config Config) http.Handler {
	if config.RequestTimeout == 0 {
		config.RequestTimeout = 12 * time.Second
	}
	a := &App{db: db, config: config}
	mux := http.NewServeMux()
	route := func(pattern string, fn endpoint) {
		mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("X-Content-Type-Options", "nosniff")
			ctx, cancel := context.WithTimeout(r.Context(), config.RequestTimeout)
			defer cancel()
			r = r.WithContext(ctx)
			if err := fn(w, r); err != nil {
				status, message := 500, "internal server error"
				var api *apiError
				if errors.As(err, &api) {
					status, message = api.status, api.message
				} else if errors.Is(err, pgx.ErrNoRows) {
					status, message = 404, "record not found"
				}
				if status == 500 {
					log.Printf("request failed: %s %s", r.Method, r.Pattern)
				}
				_ = send(w, status, map[string]any{"error": message})
			}
		})
	}
	route("GET /api/healthz", func(w http.ResponseWriter, r *http.Request) error {
		return send(w, 200, map[string]any{"status": "healthy"})
	})
	route("GET /api/readyz", func(w http.ResponseWriter, r *http.Request) error {
		if err := CheckSchema(r.Context(), db); err != nil {
			return &apiError{503, "schema not ready"}
		}
		return send(w, 200, map[string]any{"status": "ready"})
	})
	route("POST /api/auth/login", a.login)
	route("GET /api/auth/me", a.require("", a.me))
	route("POST /api/auth/logout", a.require("", a.logout))
	route("GET /api/owner/organizations", a.require("product_owner", a.listOrganizations))
	route("POST /api/owner/organizations", a.require("product_owner", a.createOrganization))
	route("POST /api/owner/organizations/{id}/admins", a.require("product_owner", a.createAdmin))
	route("GET /api/owner/organizations/{id}/keys", a.require("product_owner", a.ownerKeys))
	route("POST /api/owner/organizations/{id}/keys", a.require("product_owner", a.issueKeys))
	route("POST /api/owner/keys/{id}/revoke", a.require("product_owner", a.revokeKey))
	route("GET /api/org/keys", a.require("org", a.orgKeys))
	route("POST /api/agent/enroll", a.enroll)
	route("GET /api/agent/policy", a.device(a.agentPolicy))
	route("POST /api/agent/heartbeat", a.device(a.heartbeat))
	route("POST /api/agent/events", a.device(a.ingest))
	route("GET /api/org/devices", a.require("org", a.devices))
	route("GET /api/org/devices/{id}", a.require("org", a.deviceDetail))
	route("GET /api/org/devices/{id}/services", a.require("org", a.services))
	route("POST /api/org/devices/{id}/revoke", a.require("org_admin", a.revokeDevice))
	route("PUT /api/org/devices/{id}/employee", a.require("org_admin", a.assignEmployee))
	route("GET /api/org/reports/daily", a.require("org", a.daily))
	route("GET /api/org/settings", a.require("org", a.getSettings))
	route("PUT /api/org/settings", a.require("org_admin", a.updateSettings))
	route("GET /api/", func(w http.ResponseWriter, r *http.Request) error { return missing() })
	return mux
}

type authenticated func(http.ResponseWriter, *http.Request, principal) error

func audit(ctx context.Context, tx pgx.Tx, org, actor, action, target string) error {
	_, err := tx.Exec(ctx, "INSERT INTO audit_events(id,organization_id,actor_id,action,target_id) VALUES($1,nullif($2,''),nullif($3,''),$4,$5)", RandomToken(), org, actor, action, target)
	return err
}
