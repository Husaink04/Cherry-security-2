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
	// Bootstrap runs as the runtime role, so it may see only Product Owner rows.
	tx, err := beginScoped(ctx, db, bootstrapScope)
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

const (
	globalLoginLimit  = 180 // per minute; bounds bcrypt CPU across all clients
	clientLoginLimit  = 20  // per minute per client address
	accountLoginLimit = 5   // per 15 minutes per account email
	loginLimiterKeys  = 10000
)

type window struct {
	start time.Time
	count int
}

// windowLimiter counts attempts per key in fixed windows with a bounded key table.
type windowLimiter struct {
	mu      sync.Mutex
	limit   int
	period  time.Duration
	maxKeys int
	windows map[string]*window
}

func newWindowLimiter(limit int, period time.Duration, maxKeys int) *windowLimiter {
	return &windowLimiter{limit: limit, period: period, maxKeys: maxKeys, windows: map[string]*window{}}
}

// add records one attempt and reports whether the key remains within its limit.
func (l *windowLimiter) add(key string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	w, ok := l.windows[key]
	if ok && now.Sub(w.start) >= l.period {
		w.start, w.count = now, 0
	}
	if !ok {
		if len(l.windows) >= l.maxKeys {
			for k, old := range l.windows {
				if now.Sub(old.start) >= l.period {
					delete(l.windows, k)
				}
			}
			if len(l.windows) >= l.maxKeys {
				// Fail closed rather than grow memory without bound.
				return false
			}
		}
		w = &window{start: now}
		l.windows[key] = w
	}
	w.count++
	return w.count <= l.limit
}

func (l *windowLimiter) reset(key string) {
	l.mu.Lock()
	delete(l.windows, key)
	l.mu.Unlock()
}

// clientAddress trusts X-Real-IP only behind the bundled proxy, which overwrites that header.
func (a *App) clientAddress(r *http.Request) string {
	if a.config.TrustProxyHeader {
		if ip := net.ParseIP(strings.TrimSpace(r.Header.Get("X-Real-IP"))); ip != nil {
			return ip.String()
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// loginFailed audits a rejected password without recording the submitted email or password.
func (a *App) loginFailed(r *http.Request, org, account string) error {
	tx, err := beginScoped(r.Context(), a.db, loginScope)
	if err != nil {
		return err
	}
	defer tx.Rollback(r.Context())
	if err = audit(r.Context(), tx, org, "", "login_failed", account); err != nil {
		return err
	}
	if err = tx.Commit(r.Context()); err != nil {
		return err
	}
	return &apiError{401, "invalid credentials"}
}
func (a *App) login(w http.ResponseWriter, r *http.Request) error {
	if r.Header.Get("Origin") != a.config.Origin {
		return forbidden()
	}
	var input struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := decode(w, r, &input); err != nil {
		return err
	}
	now := time.Now()
	if !a.globalLogins.add("global", now) || !a.clientLogins.add(a.clientAddress(r), now) {
		w.Header().Set("Retry-After", "60")
		return &apiError{429, "too many login attempts; retry after one minute"}
	}
	if len(input.Password) > 72 || len(input.Email) > 254 {
		return &apiError{401, "invalid credentials"}
	}
	email := strings.ToLower(strings.TrimSpace(input.Email))
	// Unknown emails are counted the same way so lockouts do not reveal which accounts exist.
	account := digest("login:" + email)
	if !a.accountLogins.add(account, now) {
		w.Header().Set("Retry-After", "900")
		return &apiError{429, "too many login attempts for this account; retry after 15 minutes"}
	}
	var user principal
	var hash string
	// The tenant is unknown until the account is found, so this lookup uses a narrow SECURITY DEFINER function.
	err := a.db.QueryRow(r.Context(), "SELECT account_id,password_hash,account_role,organization_id FROM auth_login($1)", email).Scan(&user.ID, &hash, &user.Role, &user.OrganizationID)
	if errors.Is(err, pgx.ErrNoRows) {
		_ = bcrypt.CompareHashAndPassword([]byte("$2a$12$R9h/cIPz0gi.URNNX3kh2OPST9/PgBkqquzi.Ss7KIUgO2t0jWMUW"), []byte(input.Password))
		return a.loginFailed(r, "", "")
	}
	if err != nil {
		return err
	}
	if bcrypt.CompareHashAndPassword([]byte(hash), []byte(input.Password)) != nil {
		return a.loginFailed(r, user.OrganizationID, user.ID)
	}
	a.accountLogins.reset(account)
	token := RandomToken()
	csrf := digest("csrf:" + token)
	tx, err := beginScoped(r.Context(), a.db, user.scope())
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
		err = a.db.QueryRow(r.Context(), "SELECT account_id,account_role,organization_id,csrf_hash FROM auth_session($1)", digest(cookie.Value)).Scan(&user.ID, &user.Role, &user.OrganizationID, &user.CSRF)
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
