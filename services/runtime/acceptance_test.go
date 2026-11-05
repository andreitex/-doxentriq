package main

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestAcceptanceCommandsExecuteOfflineReadOnlyAndFailTheStage(t *testing.T) {
	calls := 0
	s := &server{runner: func(_ context.Context, name string, args ...string) (string, error) {
		calls++
		text := strings.Join(args, " ")
		for _, required := range []string{"--runtime runsc", "--network none", ",dst=/workspace,readonly", "npm_config_cache=/tmp/npm-cache", "--memory 1g", "--pids-limit 128"} {
			if !strings.Contains(text, required) {
				t.Fatalf("Missing acceptance isolation %s", required)
			}
		}
		if !strings.Contains(text, "npm run acceptance") {
			t.Fatal("Custom acceptance command was ignored")
		}
		return "The existing document cannot be opened", errors.New("exit1")
	}}
	p := Pipeline{Stages: []Stage{{Name: "acceptance", Commands: []string{"npm run acceptance", "should-not-run"}, Timeout: 60}}}
	e := s.runAcceptance(context.Background(), "attempt1", t.TempDir(), testManifest().Templates["node-api"], p)
	if e == nil || !strings.Contains(e.Error(), "existing document") || calls != 1 {
		t.Fatalf("Actual failed acceptance evidence was not preserved: %v; calls%d", e, calls)
	}
}

func TestManagedPipelineCommandsAreNeverSilentlyIgnored(t *testing.T) {
	p := Pipeline{Version: 1, Template: "node-api"}
	for _, name := range mandatoryStages {
		p.Stages = append(p.Stages, Stage{Name: name, Timeout: 60})
	}
	for i, stage := range p.Stages {
		if stage.Name == "build" || stage.Name == "application_tests" || stage.Name == "acceptance" {
			continue
		}
		p.Stages[i].Commands = []string{"exit1"}
		if validatePipeline(p, testManifest()) == nil {
			t.Fatalf("Managed command ignored in %s", stage.Name)
		}
		p.Stages[i].Commands = nil
	}
}
