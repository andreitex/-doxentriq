package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// This adapter owns an actual localhost TLS listener. In particular, ServeTLS
// returns ErrServerClosed before Shutdown has waited for an active handler.
type shutdownTestHTTP struct {
	server           *http.Server
	listener         net.Listener
	client           *http.Client
	serveReturned    chan struct{}
	shutdownReturned chan struct{}
}

func newShutdownTestHTTP(t *testing.T, handler http.HandlerFunc) *shutdownTestHTTP {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	certificate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost shutdown test"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, certificate, certificate, public, private)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(parsed)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool}, DisableKeepAlives: true}
	value := &shutdownTestHTTP{
		server:           &http.Server{Handler: handler, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: private}}}},
		listener:         listener,
		client:           &http.Client{Timeout: 3 * time.Second, Transport: transport},
		serveReturned:    make(chan struct{}),
		shutdownReturned: make(chan struct{}),
	}
	t.Cleanup(func() {
		_ = value.server.Close()
		_ = listener.Close()
		transport.CloseIdleConnections()
	})
	return value
}

func (value *shutdownTestHTTP) ListenAndServeTLS(certificate, key string) error {
	defer close(value.serveReturned)
	return value.server.ServeTLS(value.listener, certificate, key)
}

func (value *shutdownTestHTTP) Shutdown(ctx context.Context) error {
	defer close(value.shutdownReturned)
	return value.server.Shutdown(ctx)
}

func (value *shutdownTestHTTP) request() error {
	response, err := value.client.Get("https://" + value.listener.Addr().String())
	if err == nil {
		_ = response.Body.Close()
	}
	return err
}

func awaitShutdownSignal(t *testing.T, signal <-chan struct{}) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(3 * time.Second):
		t.Fatal("Timed out waiting for the test's owned operation")
	}
}

func awaitShutdownResult(t *testing.T, result <-chan error) error {
	t.Helper()
	select {
	case err := <-result:
		return err
	case <-time.After(3 * time.Second):
		t.Fatal("Runtime drain did not return within the test bound")
		return nil
	}
}

func assertShutdownPending(t *testing.T, result <-chan error) {
	t.Helper()
	select {
	case err := <-result:
		t.Fatalf("Runtime returned before its owned work completed: %v", err)
	default:
	}
}

func shutdownRelease(t *testing.T) (chan struct{}, func()) {
	t.Helper()
	channel := make(chan struct{})
	var once sync.Once
	release := func() { once.Do(func() { close(channel) }) }
	t.Cleanup(release)
	return channel, release
}

func TestRuntimeShutdownWaitsForHTTPHandlerAndAllBackgroundLoops(t *testing.T) {
	entered := make(chan struct{})
	handlerRelease, finishHandler := shutdownRelease(t)
	httpServer := newShutdownTestHTTP(t, func(w http.ResponseWriter, request *http.Request) {
		close(entered)
		<-handlerRelease
		w.WriteHeader(http.StatusNoContent)
	})
	parent, requestShutdown := context.WithCancel(context.Background())
	t.Cleanup(requestShutdown)
	backgroundContext, cancelBackground := context.WithCancel(context.Background())
	t.Cleanup(cancelBackground)
	var background []<-chan struct{}
	var finishBackground []func()
	for range 4 {
		completed := make(chan struct{})
		release, finish := shutdownRelease(t)
		background = append(background, completed)
		finishBackground = append(finishBackground, finish)
		go func() {
			defer close(completed)
			<-backgroundContext.Done()
			<-release
		}()
	}
	result := make(chan error, 1)
	go func() {
		result <- serveRuntime(parent, cancelBackground, httpServer, "", "", background, 5*time.Second)
	}()
	request := make(chan error, 1)
	go func() { request <- httpServer.request() }()
	awaitShutdownSignal(t, entered)
	requestShutdown()
	awaitShutdownSignal(t, backgroundContext.Done())
	awaitShutdownSignal(t, httpServer.serveReturned)
	// The actual listener has returned; the active request has not completed.
	assertShutdownPending(t, result)
	finishHandler()
	if err := awaitShutdownResult(t, request); err != nil {
		t.Fatal(err)
	}
	awaitShutdownSignal(t, httpServer.shutdownReturned)
	for index := range 3 {
		finishBackground[index]()
		awaitShutdownSignal(t, background[index])
	}
	assertShutdownPending(t, result)
	finishBackground[3]()
	if err := awaitShutdownResult(t, result); err != nil {
		t.Fatalf("Confirmed HTTP and all four background drains must succeed: %v", err)
	}
}

func TestRuntimeShutdownHTTPHandlerTimeoutIsFailure(t *testing.T) {
	entered := make(chan struct{})
	release, finish := shutdownRelease(t)
	httpServer := newShutdownTestHTTP(t, func(w http.ResponseWriter, request *http.Request) {
		close(entered)
		<-release
	})
	parent, requestShutdown := context.WithCancel(context.Background())
	t.Cleanup(requestShutdown)
	result := make(chan error, 1)
	go func() { result <- serveRuntime(parent, func() {}, httpServer, "", "", nil, 100*time.Millisecond) }()
	request := make(chan error, 1)
	go func() { request <- httpServer.request() }()
	awaitShutdownSignal(t, entered)
	requestShutdown()
	awaitShutdownSignal(t, httpServer.serveReturned)
	if err := awaitShutdownResult(t, result); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("A still-active HTTP handler must produce a deadline failure: %v", err)
	}
	finish()
	_ = awaitShutdownResult(t, request)
}

func TestRuntimeShutdownBackgroundTimeoutAfterHTTPCompletionIsFailure(t *testing.T) {
	httpServer := newShutdownTestHTTP(t, func(w http.ResponseWriter, request *http.Request) { w.WriteHeader(http.StatusNoContent) })
	parent, requestShutdown := context.WithCancel(context.Background())
	t.Cleanup(requestShutdown)
	release, finish := shutdownRelease(t)
	result := make(chan error, 1)
	go func() {
		result <- serveRuntime(parent, func() {}, httpServer, "", "", []<-chan struct{}{release}, 100*time.Millisecond)
	}()
	if err := httpServer.request(); err != nil {
		t.Fatal(err)
	}
	requestShutdown()
	awaitShutdownSignal(t, httpServer.shutdownReturned)
	assertShutdownPending(t, result)
	if err := awaitShutdownResult(t, result); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("An unconfirmed background loop must fail despite HTTP completion: %v", err)
	}
	finish()
}

type shutdownTestCallbacks struct {
	listen   func() error
	shutdown func(context.Context) error
}

func (value shutdownTestCallbacks) ListenAndServeTLS(string, string) error { return value.listen() }
func (value shutdownTestCallbacks) Shutdown(ctx context.Context) error     { return value.shutdown(ctx) }

func TestRuntimeShutdownNilBackgroundCompletionIsFailure(t *testing.T) {
	parent, cancel := context.WithCancel(context.Background())
	cancel()
	listenerReleased := make(chan struct{})
	value := shutdownTestCallbacks{listen: func() error { <-listenerReleased; return http.ErrServerClosed }, shutdown: func(context.Context) error { close(listenerReleased); return nil }}
	if err := serveRuntime(parent, func() {}, value, "", "", []<-chan struct{}{nil}, 20*time.Millisecond); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("A nil completion signal cannot confirm a background drain: %v", err)
	}
}

func TestRuntimeShutdownReportsHTTPShutdownError(t *testing.T) {
	parent, cancel := context.WithCancel(context.Background())
	cancel()
	expected := errors.New("Synthetic HTTP drain failure")
	listenerReleased := make(chan struct{})
	value := shutdownTestCallbacks{listen: func() error { <-listenerReleased; return http.ErrServerClosed }, shutdown: func(context.Context) error { close(listenerReleased); return expected }}
	if err := serveRuntime(parent, func() {}, value, "", "", nil, time.Second); !errors.Is(err, expected) {
		t.Fatalf("HTTP shutdown failure must remain nonzero: %v", err)
	}
}

func TestRuntimeShutdownReportsListenerFailure(t *testing.T) {
	expected := errors.New("Synthetic listener startup failure")
	background, cancel := context.WithCancel(context.Background())
	defer cancel()
	value := shutdownTestCallbacks{listen: func() error { return expected }, shutdown: func(context.Context) error { return nil }}
	if err := serveRuntime(context.Background(), cancel, value, "", "", nil, time.Second); !errors.Is(err, expected) {
		t.Fatalf("A failed listener must remain nonzero: %v", err)
	}
	if background.Err() == nil {
		t.Fatal("Listener failure must also stop new background passes")
	}
}

func TestRuntimeShutdownRejectsUnrequestedListenerClosure(t *testing.T) {
	value := shutdownTestCallbacks{listen: func() error { return http.ErrServerClosed }, shutdown: func(context.Context) error { return nil }}
	if err := serveRuntime(context.Background(), func() {}, value, "", "", nil, time.Second); err == nil {
		t.Fatal("An unexpected listener closure must not produce a successful service exit")
	}
}

func TestRuntimeShutdownRejectsInvalidOrOversizedBudgetBeforeListening(t *testing.T) {
	for name, budget := range map[string]time.Duration{"zero": 0, "negative": -time.Second, "over_fifty_seconds": 50*time.Second + time.Nanosecond} {
		t.Run(name, func(t *testing.T) {
			var canceled bool
			value := shutdownTestCallbacks{listen: func() error { t.Error("Invalid budget started a listener"); return nil }, shutdown: func(context.Context) error { t.Error("Invalid budget started shutdown"); return nil }}
			if err := serveRuntime(context.Background(), func() { canceled = true }, value, "", "", nil, budget); err == nil || !canceled {
				t.Fatalf("Invalid budget must fail and stop background work: %v", err)
			}
		})
	}
}

func TestRuntimeShutdownAllFourMaintenanceLoopsSignalCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var calls atomic.Int32
	value := &server{data: t.TempDir(), runner: func(context.Context, string, ...string) (string, error) { calls.Add(1); return "", nil }}
	loops := []<-chan struct{}{
		value.startApplicationTLSRenewal(ctx, time.Millisecond),
		value.startApplicationJWKSRefresh(ctx, time.Millisecond),
		value.startFilesystemRevocation(ctx, time.Millisecond),
		value.startConnectionWithdrawals(ctx),
	}
	for _, done := range loops {
		awaitShutdownSignal(t, done)
	}
	if calls.Load() != 0 {
		t.Fatal("Canceled maintenance loops must not begin another external operation")
	}
}
