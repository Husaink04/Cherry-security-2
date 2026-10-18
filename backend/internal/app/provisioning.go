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
		Admin    *struct {
			Email    string `json:"email"`
			Password string `json:"password"`
		} `json:"admin"`
		KeyCount int `json:"key_count"`
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
	if input.KeyCount < 0 || input.KeyCount > 100 {
		return invalid("key_count must be between 0 and 100")
	}
	// Validate and hash before the transaction so a slow bcrypt does not hold database locks.
	var email, hash string
	if input.Admin != nil {
		email = strings.ToLower(strings.TrimSpace(input.Admin.Email))
		if !validEmail(email) {
			return invalid("valid administrator email required")
		}
		var err error
		if hash, err = passwordHash(input.Admin.Password); err != nil {
			return err
		}
	}
	id := RandomToken()
	tx, err := beginScoped(r.Context(), a.db, user.scope())
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
	result := map[string]any{"id": id}
	if input.Admin != nil {
		admin := RandomToken()
		// A duplicate email rolls back the whole tenant, so no organization is left without its administrator.
		if _, err = tx.Exec(r.Context(), "INSERT INTO accounts(id,email,password_hash,role,organization_id) VALUES($1,$2,$3,'org_admin',$4)", admin, email, hash, id); err != nil {
			return conflict(err)
		}
		if err = audit(r.Context(), tx, id, user.ID, "administrator_created", admin); err != nil {
			return err
		}
		result["admin_id"] = admin
	}
	if input.KeyCount > 0 {
		keys, keyErr := issueKeysTx(r, tx, id, user.ID, input.KeyCount)
		if keyErr != nil {
			return keyErr
		}
		result["keys"] = keys
	}
	if err = tx.Commit(r.Context()); err != nil {
		return err
	}
	return send(w, 201, result)
}
func (a *App) listOrganizations(w http.ResponseWriter, r *http.Request, user principal) error {
	search := strings.TrimSpace(r.URL.Query().Get("q"))
	if len(search) > 120 {
		return invalid("search must be at most 120 bytes")
	}
	// Counts are provisioning metadata only; no activity data reaches the Product Owner.
	items := []any{}
	err := inScope(r.Context(), a.db, user.scope(), func(tx pgx.Tx) error {
		rows, err := tx.Query(r.Context(), `SELECT o.id,o.name,o.timezone,o.created_at,
 (SELECT count(*) FROM accounts a WHERE a.organization_id=o.id AND a.role='org_admin'),
 (SELECT count(*) FROM devices d WHERE d.organization_id=o.id AND d.revoked_at IS NULL),
 (SELECT count(*) FROM enrollment_keys k WHERE k.organization_id=o.id AND k.used_at IS NULL AND k.revoked_at IS NULL AND k.expires_at>now())
FROM organizations o WHERE $1='' OR position(lower($1) in lower(o.name))>0 ORDER BY o.created_at DESC LIMIT 100`, search)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var id, name, zone string
			var created time.Time
			var admins, devices, keys int64
			if err = rows.Scan(&id, &name, &zone, &created, &admins, &devices, &keys); err != nil {
				return err
			}
			items = append(items, map[string]any{"id": id, "name": name, "timezone": zone, "created_at": created, "admin_count": admins, "active_device_count": devices, "unused_key_count": keys})
		}
		return rows.Err()
	})
	if err != nil {
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
	tx, err := beginScoped(r.Context(), a.db, user.scope())
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
	tx, err := beginScoped(r.Context(), a.db, user.scope())
	if err != nil {
		return err
	}
	defer tx.Rollback(r.Context())
	var org string
	if err = tx.QueryRow(r.Context(), "SELECT id FROM organizations WHERE id=$1", r.PathValue("id")).Scan(&org); err != nil {
		return err
	}
	items, err := issueKeysTx(r, tx, org, user.ID, input.Count)
	if err != nil {
		return err
	}
	if err = tx.Commit(r.Context()); err != nil {
		return err
	}
	return send(w, 201, map[string]any{"keys": items})
}

// issueKeysTx stores only key hashes; each secret is returned once to the caller.
func issueKeysTx(r *http.Request, tx pgx.Tx, org, issuer string, count int) ([]any, error) {
	items := []any{}
	for range count {
		id, secret := RandomToken(), RandomToken()
		var expires time.Time
		if err := tx.QueryRow(r.Context(), "INSERT INTO enrollment_keys(id,organization_id,secret_hash,issuer_id,expires_at) VALUES($1,$2,$3,$4,now()+interval '24 hours') RETURNING expires_at", id, org, digest(secret), issuer).Scan(&expires); err != nil {
			return nil, err
		}
		if err := audit(r.Context(), tx, org, issuer, "enrollment_key_issued", id); err != nil {
			return nil, err
		}
		items = append(items, map[string]any{"id": id, "secret": secret, "expires_at": expires})
	}
	return items, nil
}
func (a *App) keyMetadata(w http.ResponseWriter, r *http.Request, user principal, org string) error {
	items := []any{}
	err := inScope(r.Context(), a.db, user.scope(), func(tx pgx.Tx) error {
		var exists bool
		if err := tx.QueryRow(r.Context(), "SELECT EXISTS(SELECT 1 FROM organizations WHERE id=$1)", org).Scan(&exists); err != nil {
			return err
		}
		if !exists {
			return missing()
		}
		rows, err := tx.Query(r.Context(), "SELECT id,created_at,expires_at,device_id,CASE WHEN used_at IS NOT NULL THEN 'used' WHEN revoked_at IS NOT NULL THEN 'revoked' WHEN expires_at<=now() THEN 'expired' ELSE 'unused' END FROM enrollment_keys WHERE organization_id=$1 ORDER BY created_at DESC LIMIT 500", org)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var id, status string
			var device *string
			var created, expires time.Time
			if err = rows.Scan(&id, &created, &expires, &device, &status); err != nil {
				return err
			}
			items = append(items, map[string]any{"id": id, "organization_id": org, "created_at": created, "expires_at": expires, "device_id": device, "status": status})
		}
		return rows.Err()
	})
	if err != nil {
		return err
	}
	return send(w, 200, map[string]any{"keys": items})
}
func (a *App) ownerKeys(w http.ResponseWriter, r *http.Request, user principal) error {
	return a.keyMetadata(w, r, user, r.PathValue("id"))
}
func (a *App) orgKeys(w http.ResponseWriter, r *http.Request, user principal) error {
	return a.keyMetadata(w, r, user, user.OrganizationID)
}
func (a *App) revokeKey(w http.ResponseWriter, r *http.Request, user principal) error {
	tx, err := beginScoped(r.Context(), a.db, user.scope())
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
	// The key hash identifies the tenant: claim_enrollment_key locks only the matching unused key,
	// and every later statement runs under that organization's scope.
	err = tx.QueryRow(r.Context(), "SELECT key_id,organization_id FROM claim_enrollment_key($1)", digest(input.Key)).Scan(&keyID, &org)
	if errors.Is(err, pgx.ErrNoRows) {
		return &apiError{401, "invalid or unavailable enrollment key"}
	}
	if err != nil {
		return err
	}
	if err = setScope(r.Context(), tx, tenantScope(org)); err != nil {
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
