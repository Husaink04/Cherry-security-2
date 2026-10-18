package agent

import (
	"testing"
	"time"
)

func testPolicy() Policy {
	return Policy{Version: 1, PolicyVersion: "policy-1", ServerTime: time.Date(2026, 10, 17, 9, 0, 0, 0, time.UTC), Timezone: "UTC", IdleSeconds: 300, RawRetentionDays: 7, UploadSeconds: 60, ValidForSeconds: 86400, Schedule: Schedule{Unrestricted: true}}
}

func TestPolicyValidationAndSchedule(t *testing.T) {
	policy := testPolicy()
	if err := ValidatePolicy(policy); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*Policy){func(p *Policy) { p.IdleSeconds = 59 }, func(p *Policy) { p.UploadSeconds = 301 }, func(p *Policy) { p.Timezone = "invalid" }, func(p *Policy) { p.ValidForSeconds = 86401 }, func(p *Policy) { p.Schedule = Schedule{Days: []int{1}, Start: "22:00", End: "06:00"} }} {
		invalid := policy
		mutate(&invalid)
		if ValidatePolicy(invalid) == nil {
			t.Fatal("invalid policy accepted")
		}
	}
	policy.Timezone = "Asia/Kolkata"
	policy.Schedule = Schedule{Days: []int{6}, Start: "09:00", End: "18:00"}
	if !policy.Allows(time.Date(2026, 10, 17, 3, 30, 0, 0, time.UTC)) || policy.Allows(time.Date(2026, 10, 17, 12, 30, 0, 0, time.UTC)) {
		t.Fatal("schedule boundary incorrect")
	}
}
