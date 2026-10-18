package agent

import (
	"errors"
	"time"
	_ "time/tzdata"
)

func ValidatePolicy(policy Policy) error {
	if policy.Version != 1 || len(policy.PolicyVersion) == 0 || len(policy.PolicyVersion) > 128 || policy.ServerTime.IsZero() || policy.IdleSeconds < 60 || policy.IdleSeconds > 3600 || policy.RawRetentionDays < 1 || policy.RawRetentionDays > 90 || policy.UploadSeconds < 60 || policy.UploadSeconds > 300 || policy.ValidForSeconds < 1 || policy.ValidForSeconds > 86400 {
		return errors.New("invalid policy bounds")
	}
	if policy.Timezone == "" {
		return errors.New("timezone required")
	}
	if _, err := time.LoadLocation(policy.Timezone); err != nil {
		return errors.New("invalid policy timezone")
	}
	schedule := policy.Schedule
	if schedule.Unrestricted {
		return nil
	}
	if len(schedule.Days) < 1 || len(schedule.Days) > 7 {
		return errors.New("invalid scheduled days")
	}
	seen := map[int]bool{}
	for _, day := range schedule.Days {
		if day < 0 || day > 6 || seen[day] {
			return errors.New("invalid scheduled days")
		}
		seen[day] = true
	}
	start, err := time.Parse("15:04", schedule.Start)
	if err != nil {
		return errors.New("invalid schedule start")
	}
	end, err := time.Parse("15:04", schedule.End)
	if err != nil || !end.After(start) {
		return errors.New("invalid schedule end")
	}
	return nil
}

func (policy Policy) Allows(at time.Time) bool {
	if policy.Schedule.Unrestricted {
		return true
	}
	location, err := time.LoadLocation(policy.Timezone)
	if err != nil {
		return false
	}
	local := at.In(location)
	for _, day := range policy.Schedule.Days {
		if int(local.Weekday()) == day {
			clock := local.Format("15:04")
			return clock >= policy.Schedule.Start && clock < policy.Schedule.End
		}
	}
	return false
}
