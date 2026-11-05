package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"
)

type runtimeHTTPServer interface {
	ListenAndServeTLS(string, string) error
	Shutdown(context.Context) error
}

const runtimeShutdownBudget = 50 * time.Second

// Listener closure is the beginning of HTTP Shutdown, not evidence that its
// handlers have finished. Keep the process alive until Shutdown and every
// tracked maintenance loop confirm completion within one shared budget.
// A failed drain must produce a nonzero service exit; it does not establish
// cancellation of Docker, quota, SQL or other work outside this process.
func serveRuntime(parent context.Context, cancelBackground context.CancelFunc, listener runtimeHTTPServer, certificate, key string, background []<-chan struct{}, budget time.Duration) error {
	if budget <= 0 || budget > runtimeShutdownBudget {
		cancelBackground()
		return errors.New("Runtime shutdown budget is invalid")
	}
	served := make(chan error, 1)
	go func() { served <- listener.ListenAndServeTLS(certificate, key) }()
	var serveError error
	serveFinished := false
	select {
	case <-parent.Done():
	case serveError = <-served:
		serveFinished = true
	}
	shutdownRequested := parent.Err() != nil
	drain, cancel := context.WithTimeout(context.Background(), budget)
	defer cancel()
	cancelBackground()
	shutdown := make(chan error, 1)
	go func() { shutdown <- listener.Shutdown(drain) }()
	backgroundDone := make(chan struct{})
	go func() {
		for _, done := range background {
			select {
			case <-done:
			case <-drain.Done():
				return
			}
		}
		close(backgroundDone)
	}()
	var shutdownError error
	shutdownFinished, backgroundFinished := false, false
	for !serveFinished || !shutdownFinished || !backgroundFinished {
		var servedCase <-chan error = served
		var shutdownCase <-chan error = shutdown
		var backgroundCase <-chan struct{} = backgroundDone
		if serveFinished {
			servedCase = nil
		}
		if shutdownFinished {
			shutdownCase = nil
		}
		if backgroundFinished {
			backgroundCase = nil
		}
		select {
		case serveError = <-servedCase:
			serveFinished = true
		case shutdownError = <-shutdownCase:
			shutdownFinished = true
		case <-backgroundCase:
			backgroundFinished = true
		case <-drain.Done():
			return errors.Join(errors.New("Runtime shutdown did not confirm HTTP and background completion; external operations require reconciliation"), drain.Err(), shutdownError, serveError)
		}
	}
	if drain.Err() != nil {
		return errors.Join(errors.New("Runtime shutdown exceeded its completion budget; external operations require reconciliation"), drain.Err())
	}
	if shutdownError != nil {
		return fmt.Errorf("Runtime HTTP shutdown was not confirmed: %w", shutdownError)
	}
	if serveError != nil && !errors.Is(serveError, http.ErrServerClosed) {
		return fmt.Errorf("Runtime HTTP listener failed: %w", serveError)
	}
	if !shutdownRequested {
		return errors.New("Runtime HTTP listener stopped before shutdown was requested")
	}
	return nil
}
