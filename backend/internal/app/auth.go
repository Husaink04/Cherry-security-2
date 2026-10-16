package app

import (
	"context"
	"crypto/subtle"
	"errors"
	"net"
	"net/http"
	"net/mail"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"
)

func validEmail(email string) bool {
	if len(email) > 254 {
		return false
	}
	parsed, err := mail.ParseAddress(email)
	return err == nil && parsed.Address == email && strings.Contains(email, "@")
}
func passwordHash(password string) (string, error) {
	if len(password) < 14 || len(password) > 72 {
		return "", invalid("password must contain 14 to 72 bytes")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), 12)
	return string(hash), err
}
func BootstrapOwner(ctx context.Context, db *pgxpool.Pool, email, password string) error {
	email = strings.ToLower(strings.TrimSpace(email))
	if !validEmail(email) {
		return invalid("valid email required")
	}
	hash, err := passwordHash(password)
	if err != nil {
		return err
	}
	tx, err := db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, "SELECT pg_advisory_xact_lock(472903115)"); err != nil {
		return err
	}
	var exists bool
	if err = tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM accounts WHERE role='product_owner')").Scan(&exists); err != nil {
		return err
	}
	if exists {
		return errors.New("Product Owner already exists; bootstrap will not replace it")
	}
	_, err = tx.Exec(ctx, "INSERT INTO accounts(id,email,password_hash,role) VALUES($1,$2,$3,'product_owner')", RandomToken(), email, hash)
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}

type attemptCounter struct {
	mu    sync.Mutex
	start time.Time
	count int
}

func (a *App) permitLogin(address string) bool {
	// One coarse global bucket bounds memory and avoids trusting forwarded client addresses.
	value, _ := a.loginLimits.LoadOrStore("global", &attemptCounter{start: time.Now()})
	bucket := value.(*attemptCounter)
	bucket.mu.Lock()
	defer bucket.mu.Unlock()
	if time.Since(bucket.start) > time.Minute {
		bucket.start = time.Now()
		bucket.count = 0
	}
	bucket.count++
	return bucket.count <= 30
}
func (a *App) login(w http.ResponseWriter, r *http.Request) error {
	if r.Header.Get("Origin") != a.config.Origin {
		return forbidden()
	}
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	if !a.permitLogin(host) {
		w.Header().Set("Retry-After", "60")
		return &apiError{429, "login rate limit; retry after one minute"}
	}
	var input struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := decode(w, r, &input); err != nil {
		return err
	}
	if len(input.Password) > 72 || len(input.Email) > 254 {
		return &apiError{401, "invalid credentials"}
	}
	var user principal
	var hash string
	err := a.db.QueryRow(r.Context(), "SELECT id,password_hash,role,coalesce(organization_id,'') FROM accounts WHERE email=$1", strings.ToLower(strings.TrimSpace(input.Email))).Scan(&user.ID, &hash, &user.Role, &user.OrganizationID)
	if errors.Is(err, pgx.ErrNoRows) {
		_ = bcrypt.CompareHashAndPassword([]byte("$2a$12$R9h/cIPz0gi.URNNX3kh2OPST9/PgBkqquzi.Ss7KIUgO2t0jWMUW"), []byte(input.Password))
		return &apiError{401, "invalid credentials"}
	}
	if err != nil {
		return err
	}
	if bcrypt.CompareHashAndPassword([]byte(hash), []byte(input.Password)) != nil {
		return &apiError{401, "invalid credentials"}
	}
	token := RandomToken()
	csrf := digest("csrf:" + token)
	tx, err := a.db.Begin(r.Context())
	if err != nil {
		return err
	}
	defer tx.Rollback(r.Context())
	_, err = tx.Exec(r.Context(), "INSERT INTO sessions(token_hash,account_id,csrf_hash,expires_at) VALUES($1,$2,$3,now()+interval '8 hours')", digest(token), user.ID, digest(csrf))
	if err != nil {
		return err
	}
	if err = audit(r.Context(), tx, user.OrganizationID, user.ID, "login", user.ID); err != nil {
		return err
	}
	if err = tx.Commit(r.Context()); err != nil {
		return err
	}
	http.SetCookie(w, &http.Cookie{Name: "cherry_session", Value: token, Path: "/api", HttpOnly: true, Secure: a.config.SecureCookies, SameSite: http.SameSiteStrictMode, MaxAge: 8 * 3600})
	return send(w, 200, map[string]any{"role": user.Role, "organization_id": user.OrganizationID, "csrf_token": csrf})
}
func (a *App) require(role string, fn authenticated) endpoint {
	return func(w http.ResponseWriter, r *http.Request) error {
		cookie, err := r.Cookie("cherry_session")
		if err != nil || len(cookie.Value) != 64 {
			return &apiError{401, "login required"}
		}
		var user principal
		err = a.db.QueryRow(r.Context(), "SELECT a.id,a.role,coalesce(a.organization_id,''),s.csrf_hash FROM sessions s JOIN accounts a ON a.id=s.account_id WHERE s.token_hash=$1 AND s.expires_at>now()", digest(cookie.Value)).Scan(&user.ID, &user.Role, &user.OrganizationID, &user.CSRF)
		if errors.Is(err, pgx.ErrNoRows) {
			return &apiError{401, "session expired or revoked"}
		}
		if err != nil {
			return err
		}
		if role == "org" {
			if user.Role != "org_admin" && user.Role != "org_viewer" {
				return forbidden()
			}
		} else if role != "" && user.Role != role {
			return forbidden()
		}
		if r.Method != "GET" && r.Method != "HEAD" {
			if r.Header.Get("Origin") != a.config.Origin || subtle.ConstantTimeCompare([]byte(digest(r.Header.Get("X-CSRF-Token"))), []byte(user.CSRF)) != 1 {
				return forbidden()
			}
		}
		return fn(w, r, user)
	}
}
func (a *App) me(w http.ResponseWriter, r *http.Request, user principal) error {
	// Derive the same session-bound value on reload without rotating other tabs' CSRF tokens.
	cookie, _ := r.Cookie("cherry_session")
	csrf := digest("csrf:" + cookie.Value)
	return send(w, 200, map[string]any{"role": user.Role, "organization_id": user.OrganizationID, "csrf_token": csrf})
}
func (a *App) logout(w http.ResponseWriter, r *http.Request, user principal) error {
	cookie, _ := r.Cookie("cherry_session")
	if _, err := a.db.Exec(r.Context(), "DELETE FROM sessions WHERE token_hash=$1", digest(cookie.Value)); err != nil {
		return err
	}
	http.SetCookie(w, &http.Cookie{Name: "cherry_session", Path: "/api", MaxAge: -1, HttpOnly: true, Secure: a.config.SecureCookies, SameSite: http.SameSiteStrictMode})
	return send(w, 200, map[string]any{"status": "logged out"})
}
