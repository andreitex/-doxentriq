package main

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

// An uncertain candidate must never cause a competing previous worker to start.
// The pending deployment receipt allows independent recovery after an outage.
type candidateStopUnconfirmed struct{}

func (*candidateStopUnconfirmed) Error() string {
	return "Candidate shutdown could not be independently confirmed; publication remains pending and the previous worker must remain stopped"
}

func (s *server) failedCandidate(name, appID, resourceID, image string, cause error) error {
	if err := s.stopFailedCandidate(name, appID, resourceID, image); err != nil {
		return err
	}
	return cause
}

func (s *server) stopFailedCandidate(name, appID, resourceID, image string) error {
	return s.stopRuntimeCandidate(name, appID, resourceID, image, "")
}

func (s *server) stopRuntimeCandidate(name, appID, resourceID, image, expectedID string) error {
	if !identity.MatchString(name) || !identity.MatchString(appID) || !digestImage.MatchString(image) || (resourceID != appID && resourceID != appID+"_preview") || (!strings.HasPrefix(name, "as-app-"+appID+"-") && name != "as-preview-"+appID) {
		return &candidateStopUnconfirmed{}
	}
	// Request cancellation must not skip shutdown. This bounded company cleanup
	// has no destructive actions and never removes mounts, files or volumes.
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	id, err := s.exactAppContainerID(ctx, name)
	if err != nil {
		return &candidateStopUnconfirmed{}
	}
	if id == "" {
		if expectedID != "" {
			return &candidateStopUnconfirmed{}
		}
		return nil
	}
	if expectedID != "" && id != expectedID {
		return &candidateStopUnconfirmed{}
	}
	owned, err := s.inspectTLSContainer(ctx, name, appID, resourceID, image)
	if err != nil || owned.ID != id {
		return &candidateStopUnconfirmed{}
	}
	if owned.State.Running {
		// A command error is inconclusive: inspect the immutable ID afterward.
		_, _ = s.runner(ctx, "docker", "stop", "--time", "15", id)
	}
	output, err := s.runner(ctx, "docker", "inspect", "--format", "{{json .}}", id)
	var after struct {
		ID, Name string
		State    struct{ Running, Paused, Restarting bool }
	}
	if err != nil || len(output) > 2<<20 || json.Unmarshal([]byte(output), &after) != nil || after.ID != id || after.Name != "/"+name || after.State.Running || after.State.Paused || after.State.Restarting {
		return &candidateStopUnconfirmed{}
	}
	confirmed, err := s.exactAppContainerID(ctx, name)
	if err != nil || confirmed != id {
		return &candidateStopUnconfirmed{}
	}
	return nil
}

func candidateShutdownUncertain(err error) bool {
	var uncertain *candidateStopUnconfirmed
	return errors.As(err, &uncertain)
}
