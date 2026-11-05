package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
)

type workerFence struct {
	AppID     string `json:"appId"`
	JobID     string `json:"jobId"`
	AttemptID string `json:"attemptId"`
	Fence     uint64 `json:"fence"`
}

// Caller holds the same app lock used for publication. Persist before side effects
// so a delayed request from an expired worker cannot replace a newer preview.
func (s *server) acceptFence(appID, jobID, attemptID string, fence uint64) error {
	if !identity.MatchString(appID) || !identity.MatchString(jobID) || !identity.MatchString(attemptID) || fence == 0 || fence > 9007199254740991 {
		return errors.New("A valid durable worker fence is required")
	}
	file := filepath.Join(s.data, "fences", appID+".json")
	b, e := os.ReadFile(file)
	if e == nil {
		var previous workerFence
		if json.Unmarshal(b, &previous) != nil || previous.AppID != appID || previous.Fence == 0 {
			return errors.New("The persisted worker fence is invalid")
		}
		if fence < previous.Fence || (fence == previous.Fence && (previous.JobID != jobID || previous.AttemptID != attemptID)) {
			return errors.New("Verification belongs to an expired worker; preserved work requires a new lease")
		}
		if fence == previous.Fence {
			return nil
		}
	} else if !os.IsNotExist(e) {
		return e
	}
	return atomicJSON(file, workerFence{appID, jobID, attemptID, fence})
}
