package main

import (
	"context"
	"fmt"
	"time"
)

func (s *server) runAcceptance(ctx context.Context, attemptID, workspace string, template Template, pipeline Pipeline) error {
	for _, stage := range pipeline.Stages {
		if stage.Name != "acceptance" {
			continue
		}
		for _, command := range stage.Commands {
			stageContext, cancel := context.WithTimeout(ctx, time.Duration(stage.Timeout)*time.Second)
			output, err := s.sandbox(stageContext, "as-accept-"+attemptID, workspace, template, []string{"/bin/sh", "-lc", command}, false, true)
			cancel()
			if err != nil {
				return fmt.Errorf("Custom acceptance command failed in the isolated read-only sandbox: %s", diagnosticOutput(output))
			}
		}
	}
	return nil
}
