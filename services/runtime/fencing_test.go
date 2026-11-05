package main

import "testing"

func TestPersistentWorkerFenceRejectsDelayedOrConflictingRequests(t *testing.T) {
	root := t.TempDir()
	s := &server{data: root}
	if e := s.acceptFence("app1", "job1", "attempt1", 5); e != nil {
		t.Fatal(e)
	}
	if e := s.acceptFence("app1", "job1", "attempt1", 5); e != nil {
		t.Fatal("Idempotent request rejected", e)
	}
	if s.acceptFence("app1", "job1", "attempt2", 5) == nil {
		t.Fatal("Same lease admitted a conflicting attempt")
	}
	if e := s.acceptFence("app1", "job2", "attempt2", 6); e != nil {
		t.Fatal(e)
	}
	restarted := &server{data: root}
	if restarted.acceptFence("app1", "job1", "attempt1", 5) == nil {
		t.Fatal("Delayed worker changed a newer preview after restart")
	}
	for _, fence := range []uint64{0, 9007199254740992} {
		if restarted.acceptFence("app1", "job3", "attempt3", fence) == nil {
			t.Fatal("Invalid counter admitted")
		}
	}
	if e := restarted.acceptFence("app2", "job1", "attempt1", 1); e != nil {
		t.Fatal("Another app did not have an independent fence", e)
	}
}
