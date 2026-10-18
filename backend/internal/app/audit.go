package app

import (
	"net/http"
	"regexp"
	"time"

	"github.com/jackc/pgx/v5"
)

const auditPageSize = 100

var auditActions = []string{"login", "login_failed", "settings_updated", "device_revoked", "device_employee_assigned", "enrollment_key_issued", "enrollment_key_revoked", "enrollment_key_redeemed", "administrator_created", "organization_created"}

var auditIDPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

// Actors and targets resolve only within the caller's organization; the Product Owner is never named,
// and is recognized through is_product_owner because tenant transactions cannot read that account.
const auditQuery = `SELECT jsonb_build_object('id',e.id,'action',e.action,'created_at',e.created_at,'target_id',e.target_id,
 'actor',CASE WHEN e.actor_id IS NULL THEN 'system' WHEN is_product_owner(e.actor_id) THEN 'Product Owner' WHEN member.id IS NOT NULL THEN member.email WHEN device.id IS NOT NULL THEN 'device '||device.hostname ELSE 'unknown' END,
 'target',coalesce(target_member.email,target_device.hostname,''))
FROM audit_events e
LEFT JOIN accounts member ON member.id=e.actor_id AND member.organization_id=e.organization_id
LEFT JOIN devices device ON device.id=e.actor_id AND device.organization_id=e.organization_id
LEFT JOIN accounts target_member ON target_member.id=e.target_id AND target_member.organization_id=e.organization_id
LEFT JOIN devices target_device ON target_device.id=e.target_id AND target_device.organization_id=e.organization_id
WHERE e.organization_id=$1 AND ($2='' OR e.action=$2) AND ($3::timestamptz IS NULL OR (e.created_at,e.id)<($3::timestamptz,$4))
ORDER BY e.created_at DESC,e.id DESC LIMIT $5`

func (a *App) orgAudit(w http.ResponseWriter, r *http.Request, user principal) error {
	query := r.URL.Query()
	action := query.Get("action")
	if action != "" && !allowed(action, auditActions...) {
		return invalid("unsupported audit action filter")
	}
	var before *time.Time
	beforeID := query.Get("before_id")
	if raw := query.Get("before"); raw != "" || beforeID != "" {
		// Events created in one transaction share a timestamp, so paging needs the ID as a tiebreaker.
		parsed, err := time.Parse(time.RFC3339Nano, raw)
		if err != nil || !auditIDPattern.MatchString(beforeID) {
			return invalid("before must be an RFC 3339 time and before_id an audit event ID")
		}
		before = &parsed
	}
	var items []any
	err := inScope(r.Context(), a.db, user.scope(), func(tx pgx.Tx) (err error) {
		items, err = jsonRows(r.Context(), tx, auditQuery, user.OrganizationID, action, before, beforeID, auditPageSize+1)
		return err
	})
	if err != nil {
		return err
	}
	more := len(items) > auditPageSize
	if more {
		items = items[:auditPageSize]
	}
	return send(w, 200, map[string]any{"events": items, "has_more": more, "limit": auditPageSize, "retention_days": 90})
}
