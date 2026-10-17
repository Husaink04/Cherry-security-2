package app

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

func conflict(err error) error {
	var pg *pgconn.PgError
	if errors.As(err, &pg) && pg.Code == "23505" {
		return &apiError{409, "record already exists"}
	}
	return err
}
func (a *App) createOrganization(w http.ResponseWriter, r *http.Request, user principal) error {
	var input struct {
		Name     string `json:"name"`
		Timezone string `json:"timezone"`
	}
	if err := decode(w, r, &input); err != nil {
		return err
	}
	input.Name = strings.TrimSpace(input.Name)
	if len(input.Name) < 1 || len(input.Name) > 120 {
		return invalid("organization name must be 1 to 120 bytes")
	}
	if _, err := time.LoadLocation(input.Timezone); err != nil || input.Timezone == "" {
		return invalid("valid IANA timezone required")
	}
	id := RandomToken()
	tx, err := a.db.Begin(r.Context())
	if err != nil {
		return err
	}
	defer tx.Rollback(r.Context())
	if _, err = tx.Exec(r.Context(), "INSERT INTO organizations(id,name,timezone) VALUES($1,$2,$3)", id, input.Name, input.Timezone); err != nil {
		return err
	}
	if err = audit(r.Context(), tx, id, user.ID, "organization_created", id); err != nil {
		return err
	}
	if err = tx.Commit(r.Context()); err != nil {
		return err
	}
	return send(w, 201, map[string]any{"id": id})
}
func (a *App) listOrganizations(w http.ResponseWriter, r *http.Request, user principal) error {
	rows, err := a.db.Query(r.Context(), "SELECT id,name,timezone,created_at FROM organizations ORDER BY created_at DESC LIMIT 100")
	if err != nil {
		return err
	}
	defer rows.Close()
	items := []any{}
	for rows.Next() {
		var id, name, zone string
		var created time.Time
		if err = rows.Scan(&id, &name, &zone, &created); err != nil {
			return err
		}
		items = append(items, map[string]any{"id": id, "name": name, "timezone": zone, "created_at": created})
	}
	if err = rows.Err(); err != nil {
		return err
	}
	return send(w, 200, map[string]any{"organizations": items})
}
func (a *App) createAdmin(w http.ResponseWriter, r *http.Request, user principal) error {
	var input struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := decode(w, r, &input); err != nil {
		return err
	}
	input.Email = strings.ToLower(strings.TrimSpace(input.Email))
	if !validEmail(input.Email) {
		return invalid("valid email required")
	}
	hash, err := passwordHash(input.Password)
	if err != nil {
		return err
	}
	tx, err := a.db.Begin(r.Context())
	if err != nil {
		return err
	}
	defer tx.Rollback(r.Context())
	var org string
	if err = tx.QueryRow(r.Context(), "SELECT id FROM organizations WHERE id=$1", r.PathValue("id")).Scan(&org); err != nil {
		return err
	}
	id := RandomToken()
	if _, err = tx.Exec(r.Context(), "INSERT INTO accounts(id,email,password_hash,role,organization_id) VALUES($1,$2,$3,'org_admin',$4)", id, input.Email, hash, org); err != nil {
		return conflict(err)
	}
	if err = audit(r.Context(), tx, org, user.ID, "administrator_created", id); err != nil {
		return err
	}
	if err = tx.Commit(r.Context()); err != nil {
		return err
	}
	return send(w, 201, map[string]any{"id": id})
}
func (a *App) issueKeys(w http.ResponseWriter, r *http.Request, user principal) error {
	var input struct {
		Count int `json:"count"`
	}
	if err := decode(w, r, &input); err != nil {
		return err
	}
	if input.Count < 1 || input.Count > 100 {
		return invalid("count must be between 1 and 100")
	}
	tx, err := a.db.Begin(r.Context())
	if err != nil {
		return err
	}
	defer tx.Rollback(r.Context())
	var org string
	if err = tx.QueryRow(r.Context(), "SELECT id FROM organizations WHERE id=$1", r.PathValue("id")).Scan(&org); err != nil {
		return err
	}
	items := []any{}
	for range input.Count {
		id, secret := RandomToken(), RandomToken()
		var expires time.Time
		if err = tx.QueryRow(r.Context(), "INSERT INTO enrollment_keys(id,organization_id,secret_hash,issuer_id,expires_at) VALUES($1,$2,$3,$4,now()+interval '24 hours') RETURNING expires_at", id, org, digest(secret), user.ID).Scan(&expires); err != nil {
			return err
		}
		if err = audit(r.Context(), tx, org, user.ID, "enrollment_key_issued", id); err != nil {
			return err
		}
		items = append(items, map[string]any{"id": id, "secret": secret, "expires_at": expires})
	}
	if err = tx.Commit(r.Context()); err != nil {
		return err
	}
	return send(w, 201, map[string]any{"keys": items})
}
func (a *App) keyMetadata(w http.ResponseWriter, r *http.Request, org string) error {
	var exists bool
	if err := a.db.QueryRow(r.Context(), "SELECT EXISTS(SELECT 1 FROM organizations WHERE id=$1)", org).Scan(&exists); err != nil {
		return err
	}
	if !exists {
		return missing()
	}
	rows, err := a.db.Query(r.Context(), "SELECT id,created_at,expires_at,device_id,CASE WHEN used_at IS NOT NULL THEN 'used' WHEN revoked_at IS NOT NULL THEN 'revoked' WHEN expires_at<=now() THEN 'expired' ELSE 'unused' END FROM enrollment_keys WHERE organization_id=$1 ORDER BY created_at DESC LIMIT 500", org)
	if err != nil {
		return err
	}
	defer rows.Close()
	items := []any{}
	for rows.Next() {
		var id, status string
		var device *string
		var created, expires time.Time
		if err = rows.Scan(&id, &created, &expires, &device, &status); err != nil {
			return err
		}
		items = append(items, map[string]any{"id": id, "organization_id": org, "created_at": created, "expires_at": expires, "device_id": device, "status": status})
	}
	if err = rows.Err(); err != nil {
		return err
	}
	return send(w, 200, map[string]any{"keys": items})
}
func (a *App) ownerKeys(w http.ResponseWriter, r *http.Request, user principal) error {
	return a.keyMetadata(w, r, r.PathValue("id"))
}
func (a *App) orgKeys(w http.ResponseWriter, r *http.Request, user principal) error {
	return a.keyMetadata(w, r, user.OrganizationID)
}
func (a *App) revokeKey(w http.ResponseWriter, r *http.Request, user principal) error {
	tx, err := a.db.Begin(r.Context())
	if err != nil {
		return err
	}
	defer tx.Rollback(r.Context())
	var org string
	err = tx.QueryRow(r.Context(), "UPDATE enrollment_keys SET revoked_at=coalesce(revoked_at,now()) WHERE id=$1 AND used_at IS NULL RETURNING organization_id", r.PathValue("id")).Scan(&org)
	if errors.Is(err, pgx.ErrNoRows) {
		return &apiError{404, "unused key not found"}
	}
	if err != nil {
		return err
	}
	if err = audit(r.Context(), tx, org, user.ID, "enrollment_key_revoked", r.PathValue("id")); err != nil {
		return err
	}
	if err = tx.Commit(r.Context()); err != nil {
		return err
	}
	return send(w, 200, map[string]any{"status": "revoked"})
}
func (a *App) enroll(w http.ResponseWriter, r *http.Request) error {
	var input struct {
		Key       string `json:"enrollment_key"`
		Hostname  string `json:"hostname"`
		OS        string `json:"os"`
		Version   string `json:"agent_version"`
		Simulated bool   `json:"simulated"`
	}
	if err := decode(w, r, &input); err != nil {
		return err
	}
	if len(input.Key) != 64 {
		return &apiError{401, "invalid or unavailable enrollment key"}
	}
	if len(input.Hostname) < 1 || len(input.Hostname) > 120 || len(input.OS) < 1 || len(input.OS) > 120 || len(input.Version) < 1 || len(input.Version) > 40 {
		return invalid("hostname, OS, and version required within supported limits")
	}
	tx, err := a.db.Begin(r.Context())
	if err != nil {
		return err
	}
	defer tx.Rollback(r.Context())
	var keyID, org string
	err = tx.QueryRow(r.Context(), "SELECT id,organization_id FROM enrollment_keys WHERE secret_hash=$1 AND used_at IS NULL AND revoked_at IS NULL AND expires_at>now() FOR UPDATE", digest(input.Key)).Scan(&keyID, &org)
	if errors.Is(err, pgx.ErrNoRows) {
		return &apiError{401, "invalid or unavailable enrollment key"}
	}
	if err != nil {
		return err
	}
	id, token := RandomToken(), RandomToken()
	_, err = tx.Exec(r.Context(), "INSERT INTO devices(id,organization_id,hostname,os,agent_version,simulated,token_hash) VALUES($1,$2,$3,$4,$5,$6,$7)", id, org, input.Hostname, input.OS, input.Version, input.Simulated, digest(token))
	if err != nil {
		return err
	}
	if _, err = tx.Exec(r.Context(), "UPDATE enrollment_keys SET used_at=now(),device_id=$1 WHERE id=$2", id, keyID); err != nil {
		return err
	}
	if err = audit(r.Context(), tx, org, id, "enrollment_key_redeemed", keyID); err != nil {
		return err
	}
	if err = tx.Commit(r.Context()); err != nil {
		return err
	}
	return send(w, 201, map[string]any{"device_id": id, "device_token": token})
}
