package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Oudwins/mcp-auth-proxy/internal/config"
)

var clockStart = time.UnixMilli(1_700_000_000_000).UTC()

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) advance(seconds int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(time.Duration(seconds) * time.Second)
}

type recordingLogger struct {
	mu    sync.Mutex
	lines map[string][]string
}

func (l *recordingLogger) record(level, format string, args []any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.lines == nil {
		l.lines = map[string][]string{}
	}
	l.lines[level] = append(l.lines[level], fmt.Sprintf(format, args...))
}

func (l *recordingLogger) got(level string) []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.lines[level]...)
}

func (l *recordingLogger) Debug(format string, args ...any) { l.record("debug", format, args) }
func (l *recordingLogger) Info(format string, args ...any)  { l.record("info", format, args) }
func (l *recordingLogger) Warn(format string, args ...any)  { l.record("warn", format, args) }
func (l *recordingLogger) Error(format string, args ...any) { l.record("error", format, args) }

type behavior func(ctx context.Context, run int) (string, error)

type harness struct {
	provider *Provider
	clock    *fakeClock
	log      *recordingLogger

	mu       sync.Mutex
	runs     int
	contexts []Context
	ctxs     []context.Context
	impl     behavior
}

func output(token string, lifetimeSeconds int) string {
	return jsonOf(map[string]any{"values": map[string]string{"token": token}, "expiresInSeconds": lifetimeSeconds})
}

func newHarness(mods ...func(*config.Strategy)) *harness {
	h := &harness{clock: &fakeClock{t: clockStart}, log: &recordingLogger{}}
	h.impl = func(_ context.Context, run int) (string, error) { return output(fmt.Sprintf("t%d", run), 100), nil }
	strategy := makeStrategy(func(s *config.Strategy) {
		s.Output = "json"
		s.RefreshSkew = 10 * time.Second
		s.RetryCooldown = 0
	})
	for _, mod := range mods {
		mod(&strategy)
	}
	h.provider = NewProvider(ProviderOptions{
		Name:     "up",
		Strategy: strategy,
		Log:      h.log,
		Now:      h.clock.Now,
		Run: func(ctx context.Context, _ config.Strategy, rc Context) (string, error) {
			h.mu.Lock()
			h.runs++
			run := h.runs
			h.contexts = append(h.contexts, rc)
			h.ctxs = append(h.ctxs, ctx)
			impl := h.impl
			h.mu.Unlock()
			return impl(ctx, run)
		},
	})
	return h
}

func (h *harness) respond(impl behavior) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.impl = impl
}

func (h *harness) respondWith(stdout string) {
	h.respond(func(context.Context, int) (string, error) { return stdout, nil })
}

func (h *harness) respondFail(message string) {
	h.respond(func(context.Context, int) (string, error) { return "", &CommandError{Message: message} })
}

func (h *harness) runCount() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.runs
}

func (h *harness) seenContexts() []Context {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]Context(nil), h.contexts...)
}

type gate struct {
	started chan struct{}
	release chan gateResult
	once    sync.Once
}

type gateResult struct {
	stdout string
	err    error
}

func (g *gate) wait(ctx context.Context, _ int) (string, error) {
	g.once.Do(func() { close(g.started) })
	select {
	case r := <-g.release:
		return r.stdout, r.err
	case <-ctx.Done():
		return "", ctx.Err()
	case <-time.After(5 * time.Second):
		return "", errors.New("gate was never released")
	}
}

func (g *gate) open(stdout string, err error) { g.release <- gateResult{stdout, err} }

func (h *harness) block() *gate {
	g := &gate{started: make(chan struct{}), release: make(chan gateResult, 1)}
	h.respond(g.wait)
	return g
}

func (g *gate) waitStarted(t *testing.T) {
	t.Helper()
	select {
	case <-g.started:
	case <-time.After(5 * time.Second):
		t.Fatal("the generator never started")
	}
}

func (h *harness) waitForWaiters(t *testing.T, n int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		h.provider.mu.Lock()
		got := 0
		if h.provider.inflight != nil {
			got = h.provider.inflight.waiters
		}
		h.provider.mu.Unlock()
		if got >= n {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("fewer than %d callers joined the refresh", n)
}

type getResult struct {
	creds *Credentials
	err   error
}

func goGet(p *Provider, ctx context.Context) <-chan getResult {
	ch := make(chan getResult, 1)
	go func() {
		creds, err := p.Get(ctx)
		ch <- getResult{creds, err}
	}()
	return ch
}

func goRefreshAfterRejection(p *Provider, ctx context.Context, rejected *Credentials) <-chan getResult {
	ch := make(chan getResult, 1)
	go func() {
		creds, err := p.RefreshAfterRejection(ctx, rejected)
		ch <- getResult{creds, err}
	}()
	return ch
}

func receive(t *testing.T, ch <-chan getResult) getResult {
	t.Helper()
	select {
	case r := <-ch:
		return r
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for the call to return")
		return getResult{}
	}
}

func mustGet(t *testing.T, h *harness) *Credentials {
	t.Helper()
	creds, err := h.provider.Get(context.Background())
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	return creds
}

func tokenOf(c *Credentials) string {
	if c == nil {
		return "<nil>"
	}
	return c.Values["token"]
}

func expectToken(t *testing.T, c *Credentials, want string) {
	t.Helper()
	if got := tokenOf(c); got != want {
		t.Errorf("token = %q, want %q", got, want)
	}
}

func expectRuns(t *testing.T, h *harness, want int) {
	t.Helper()
	if got := h.runCount(); got != want {
		t.Errorf("generator ran %d times, want %d", got, want)
	}
}

func expectErrContains(t *testing.T, err error, want string) {
	t.Helper()
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Errorf("err = %v, want it to contain %q", err, want)
	}
}

func TestGet(t *testing.T) {
	t.Run("caches credentials until the skew window", func(t *testing.T) {
		h := newHarness()
		first := mustGet(t, h)
		h.clock.advance(89)
		second := mustGet(t, h)

		if second != first {
			t.Error("expected the cached credentials")
		}
		expectRuns(t, h, 1)
	})

	t.Run("refreshes once inside the skew window", func(t *testing.T) {
		h := newHarness()
		mustGet(t, h)
		h.clock.advance(91)
		refreshed := mustGet(t, h)

		expectRuns(t, h, 2)
		expectToken(t, refreshed, "t2")
		if refreshed.Version != 2 {
			t.Errorf("Version = %d, want 2", refreshed.Version)
		}
	})

	t.Run("refreshes exactly at the start of the skew window", func(t *testing.T) {
		h := newHarness()
		mustGet(t, h)
		h.clock.advance(90)
		mustGet(t, h)

		expectRuns(t, h, 2)
	})

	t.Run("passes the strategy name and forced flag to the generator", func(t *testing.T) {
		h := newHarness()
		mustGet(t, h)

		if got, want := h.seenContexts(), []Context{{Strategy: "up", Forced: false}}; !reflect.DeepEqual(got, want) {
			t.Errorf("contexts = %v, want %v", got, want)
		}
	})

	t.Run("returns the values, expiry and version of the generated credentials", func(t *testing.T) {
		h := newHarness()
		got := mustGet(t, h)

		want := &Credentials{
			Values:       map[string]string{"token": "t1"},
			ExpiresAt:    clockStart.Add(100 * time.Second),
			ExpirySource: "output",
			Version:      1,
		}
		if !reflect.DeepEqual(got.Values, want.Values) || !got.ExpiresAt.Equal(want.ExpiresAt) ||
			got.ExpirySource != want.ExpirySource || got.Version != want.Version {
			t.Errorf("credentials = %+v, want %+v", got, want)
		}
	})

	t.Run("shares one generator run between concurrent callers", func(t *testing.T) {
		h := newHarness()
		g := h.block()

		first := goGet(h.provider, context.Background())
		g.waitStarted(t)
		pending := []<-chan getResult{first, goGet(h.provider, context.Background()), goGet(h.provider, context.Background())}
		h.waitForWaiters(t, 3)
		g.open(output("shared", 100), nil)

		for _, ch := range pending {
			r := receive(t, ch)
			if r.err != nil {
				t.Fatalf("Get failed: %v", r.err)
			}
			expectToken(t, r.creds, "shared")
		}
		expectRuns(t, h, 1)
	})

	t.Run("serves many goroutines from a single run", func(t *testing.T) {
		h := newHarness()
		var wg sync.WaitGroup
		for range 32 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if _, err := h.provider.Get(context.Background()); err != nil {
					t.Errorf("Get failed: %v", err)
				}
			}()
		}
		wg.Wait()

		expectRuns(t, h, 1)
	})

	t.Run("reuses unexpired credentials when a refresh fails, then fails once they expire", func(t *testing.T) {
		h := newHarness()
		first := mustGet(t, h)
		h.respondFail("gcloud exploded")

		h.clock.advance(95)
		second, err := h.provider.Get(context.Background())
		if err != nil || second != first {
			t.Fatalf("Get = %v, %v; want the stale credentials", second, err)
		}
		if len(h.log.got("warn")) == 0 {
			t.Error("expected a warning about reusing credentials")
		}

		h.clock.advance(6)
		_, err = h.provider.Get(context.Background())
		expectErrContains(t, err, "gcloud exploded")
	})

	t.Run("surfaces an initial failure and recovers on the next call", func(t *testing.T) {
		h := newHarness()
		h.respondFail("not logged in")

		_, err := h.provider.Get(context.Background())
		expectErrContains(t, err, "not logged in")
		status := h.provider.Status()
		if status.HasCredentials || status.LastError == nil || *status.LastError != "not logged in" {
			t.Errorf("status = %+v", status)
		}

		h.respondWith(output("good", 100))
		expectToken(t, mustGet(t, h), "good")
		if h.provider.Status().LastError != nil {
			t.Error("lastError should be cleared after a successful refresh")
		}
	})

	t.Run("returns the generator error as a CommandError", func(t *testing.T) {
		h := newHarness()
		h.respondFail("boom")

		_, err := h.provider.Get(context.Background())
		var ce *CommandError
		if !errors.As(err, &ce) || ce.Message != "boom" {
			t.Errorf("err = %#v", err)
		}
	})

	t.Run("logs failures and successes", func(t *testing.T) {
		h := newHarness()
		h.respondFail("nope")
		_, _ = h.provider.Get(context.Background())
		h.respondWith(output("ok", 100))
		mustGet(t, h)

		if got := h.log.got("error"); !reflect.DeepEqual(got, []string{"[up] nope"}) {
			t.Errorf("errors = %v", got)
		}
		info := h.log.got("info")
		if len(info) != 1 || !strings.Contains(info[0], "(initial)") || !strings.Contains(info[0], "via output") ||
			!strings.Contains(info[0], "2023-11-14T22:15:00.000Z") {
			t.Errorf("info = %v", info)
		}
	})

	t.Run("does not log credential values", func(t *testing.T) {
		h := newHarness()
		h.respondWith(output("secret-token-value", 100))
		mustGet(t, h)

		for level, lines := range h.log.lines {
			for _, line := range lines {
				if strings.Contains(line, "secret-token-value") {
					t.Errorf("%s log line leaks a value: %q", level, line)
				}
			}
		}
	})

	t.Run("treats unparseable generator output as a failure", func(t *testing.T) {
		h := newHarness()
		h.respondWith("not json")

		_, err := h.provider.Get(context.Background())
		expectErrContains(t, err, "not valid JSON")
	})

	t.Run("treats generator output with the wrong shape as a failure", func(t *testing.T) {
		h := newHarness()
		h.respondWith(jsonOf(map[string]any{"headers": map[string]string{"Authorization": "Bearer x"}}))

		_, err := h.provider.Get(context.Background())
		expectErrContains(t, err, "wrong shape")
	})

	t.Run("parses bare tokens when the strategy output is token", func(t *testing.T) {
		h := newHarness(func(s *config.Strategy) { s.Output, s.TTL = "token", 50*time.Second })
		h.respondWith("bare-token\n")

		got := mustGet(t, h)
		if !reflect.DeepEqual(got.Values, map[string]string{"token": "bare-token"}) {
			t.Errorf("Values = %v", got.Values)
		}
		if got.ExpirySource != "ttl" || !got.ExpiresAt.Equal(clockStart.Add(50*time.Second)) {
			t.Errorf("expiry = %v via %s", got.ExpiresAt, got.ExpirySource)
		}
	})

	t.Run("refreshes ttl based credentials using the strategy skew", func(t *testing.T) {
		h := newHarness(func(s *config.Strategy) {
			s.Output, s.TTL, s.RefreshSkew = "token", 50*time.Second, 20*time.Second
		})
		h.respondWith("bare-token")
		mustGet(t, h)

		h.clock.advance(29)
		mustGet(t, h)
		expectRuns(t, h, 1)

		h.clock.advance(2)
		mustGet(t, h)
		expectRuns(t, h, 2)
	})

	t.Run("an expiring refresh is logged as expiring", func(t *testing.T) {
		h := newHarness()
		mustGet(t, h)
		h.clock.advance(95)
		mustGet(t, h)

		info := h.log.got("info")
		if len(info) != 2 || !strings.Contains(info[1], "(expiring)") {
			t.Errorf("info = %v", info)
		}
	})
}

func TestGetContext(t *testing.T) {
	t.Run("a waiter stops waiting when its own context ends while others still get the result", func(t *testing.T) {
		h := newHarness()
		g := h.block()
		ctx, cancel := context.WithCancel(context.Background())

		cancelled := goGet(h.provider, ctx)
		g.waitStarted(t)
		patient := goGet(h.provider, context.Background())
		h.waitForWaiters(t, 2)
		cancel()

		if r := receive(t, cancelled); !errors.Is(r.err, context.Canceled) {
			t.Errorf("err = %v, want context.Canceled", r.err)
		}
		g.open(output("shared", 100), nil)
		r := receive(t, patient)
		if r.err != nil {
			t.Fatalf("Get failed: %v", r.err)
		}
		expectToken(t, r.creds, "shared")
		expectRuns(t, h, 1)
	})

	t.Run("a cancelled caller does not abort the refresh it started", func(t *testing.T) {
		h := newHarness()
		var seen context.Context
		release := make(chan struct{})
		started := make(chan struct{})
		h.respond(func(ctx context.Context, _ int) (string, error) {
			seen = ctx
			close(started)
			<-release
			return output("kept", 100), nil
		})
		ctx, cancel := context.WithCancel(context.Background())

		first := goGet(h.provider, ctx)
		<-started
		cancel()
		receive(t, first)
		if seen.Err() != nil {
			t.Fatalf("generator context was cancelled: %v", seen.Err())
		}
		close(release)

		deadline := time.Now().Add(5 * time.Second)
		for !h.provider.Status().HasCredentials && time.Now().Before(deadline) {
			time.Sleep(time.Millisecond)
		}
		expectToken(t, mustGet(t, h), "kept")
		expectRuns(t, h, 1)
	})

	t.Run("a cancelled caller does not fall back to stale credentials", func(t *testing.T) {
		h := newHarness()
		first := mustGet(t, h)
		h.clock.advance(95)
		g := h.block()
		ctx, cancel := context.WithCancel(context.Background())

		pending := goGet(h.provider, ctx)
		g.waitStarted(t)
		cancel()

		r := receive(t, pending)
		if !errors.Is(r.err, context.Canceled) || r.creds != nil {
			t.Errorf("got %v, %v; want context.Canceled (stale was %v)", r.creds, r.err, first)
		}
		g.open(output("late", 100), nil)
	})

	t.Run("the generator context carries the strategy timeout", func(t *testing.T) {
		h := newHarness(func(s *config.Strategy) { s.Timeout = 7 * time.Second })
		mustGet(t, h)

		h.mu.Lock()
		defer h.mu.Unlock()
		deadline, ok := h.ctxs[0].Deadline()
		if !ok || time.Until(deadline) > 7*time.Second || time.Until(deadline) < 5*time.Second {
			t.Errorf("deadline = %v, %v", deadline, ok)
		}
	})

	t.Run("a generator that outlives the strategy timeout is cut off with its context", func(t *testing.T) {
		h := newHarness(func(s *config.Strategy) { s.Timeout = 50 * time.Millisecond })
		h.respond(func(ctx context.Context, _ int) (string, error) {
			<-ctx.Done()
			return "", ctx.Err()
		})

		_, err := h.provider.Get(context.Background())
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("err = %v, want deadline exceeded", err)
		}
	})
}

func TestRefreshAfterRejection(t *testing.T) {
	t.Run("runs the generator with the forced flag and returns the new credentials", func(t *testing.T) {
		h := newHarness()
		rejected := mustGet(t, h)

		next, err := h.provider.RefreshAfterRejection(context.Background(), rejected)
		if err != nil {
			t.Fatal(err)
		}
		expectToken(t, next, "t2")
		if got, want := h.seenContexts(), []Context{{"up", false}, {"up", true}}; !reflect.DeepEqual(got, want) {
			t.Errorf("contexts = %v, want %v", got, want)
		}
		if info := h.log.got("info"); len(info) != 2 || !strings.Contains(info[1], "after upstream rejection") {
			t.Errorf("info = %v", info)
		}
	})

	t.Run("returns nil when the generator produces the same values again", func(t *testing.T) {
		h := newHarness()
		h.respondWith(output("same", 100))
		rejected := mustGet(t, h)

		next, err := h.provider.RefreshAfterRejection(context.Background(), rejected)
		if next != nil || err != nil {
			t.Errorf("got %v, %v; want nil, nil", next, err)
		}
		expectRuns(t, h, 2)
	})

	t.Run("treats values as the same regardless of key order", func(t *testing.T) {
		h := newHarness()
		h.respondWith(`{"values":{"a":"1","b":"2"},"expiresInSeconds":100}`)
		rejected := mustGet(t, h)
		h.respondWith(`{"values":{"b":"2","a":"1"},"expiresInSeconds":100}`)

		next, err := h.provider.RefreshAfterRejection(context.Background(), rejected)
		if next != nil || err != nil {
			t.Errorf("got %v, %v; want nil, nil", next, err)
		}
	})

	t.Run("returns new credentials when only one of several values changed", func(t *testing.T) {
		h := newHarness()
		h.respondWith(`{"values":{"a":"1","b":"2"},"expiresInSeconds":100}`)
		rejected := mustGet(t, h)
		h.respondWith(`{"values":{"a":"1","b":"3"},"expiresInSeconds":100}`)

		next, err := h.provider.RefreshAfterRejection(context.Background(), rejected)
		if err != nil || next == nil {
			t.Fatalf("got %v, %v", next, err)
		}
		if !reflect.DeepEqual(next.Values, map[string]string{"a": "1", "b": "3"}) {
			t.Errorf("Values = %v", next.Values)
		}
	})

	t.Run("returns newer credentials without running the generator when another request already refreshed", func(t *testing.T) {
		h := newHarness()
		stale := mustGet(t, h)
		h.clock.advance(95)
		fresh := mustGet(t, h)

		next, err := h.provider.RefreshAfterRejection(context.Background(), stale)
		if err != nil || next != fresh {
			t.Errorf("got %v, %v; want the fresh credentials", next, err)
		}
		expectRuns(t, h, 2)
	})

	t.Run("joins a refresh that is already running", func(t *testing.T) {
		h := newHarness()
		stale := mustGet(t, h)
		h.clock.advance(95)
		g := h.block()

		refreshing := goGet(h.provider, context.Background())
		g.waitStarted(t)
		rejection := goRefreshAfterRejection(h.provider, context.Background(), stale)
		h.waitForWaiters(t, 2)
		g.open(output("fresh", 100), nil)

		r := receive(t, refreshing)
		expectToken(t, r.creds, "fresh")
		r = receive(t, rejection)
		if r.err != nil {
			t.Fatal(r.err)
		}
		expectToken(t, r.creds, "fresh")
		expectRuns(t, h, 2)
	})

	t.Run("returns nil when the joined refresh produced the rejected credentials", func(t *testing.T) {
		h := newHarness()
		g := h.block()

		first := goGet(h.provider, context.Background())
		g.waitStarted(t)
		rejection := goRefreshAfterRejection(h.provider, context.Background(), &Credentials{Values: map[string]string{"token": "x"}, Version: 1})
		h.waitForWaiters(t, 2)
		g.open(output("fresh", 100), nil)

		receive(t, first)
		if r := receive(t, rejection); r.creds != nil || r.err != nil {
			t.Errorf("got %v, %v; want nil, nil", r.creds, r.err)
		}
	})

	t.Run("returns nil when the refresh it joined fails", func(t *testing.T) {
		h := newHarness()
		stale := mustGet(t, h)
		h.clock.advance(95)
		g := h.block()

		refreshing := goGet(h.provider, context.Background())
		g.waitStarted(t)
		rejection := goRefreshAfterRejection(h.provider, context.Background(), stale)
		h.waitForWaiters(t, 2)
		g.open("", &CommandError{Message: "boom"})

		if r := receive(t, refreshing); r.err != nil || r.creds != stale {
			t.Errorf("Get = %v, %v; want the stale credentials", r.creds, r.err)
		}
		if r := receive(t, rejection); r.creds != nil || r.err != nil {
			t.Errorf("got %v, %v; want nil, nil", r.creds, r.err)
		}
	})

	t.Run("ignores rejections inside the cooldown window and acts again after it", func(t *testing.T) {
		h := newHarness(func(s *config.Strategy) { s.RetryCooldown = 5 * time.Second })
		rejected := mustGet(t, h)

		h.clock.advance(1)
		next, err := h.provider.RefreshAfterRejection(context.Background(), rejected)
		if next != nil || err != nil {
			t.Errorf("got %v, %v; want nil, nil", next, err)
		}
		expectRuns(t, h, 1)
		if len(h.log.got("debug")) != 1 {
			t.Errorf("debug = %v", h.log.got("debug"))
		}

		h.clock.advance(5)
		next, err = h.provider.RefreshAfterRejection(context.Background(), rejected)
		if err != nil {
			t.Fatal(err)
		}
		expectToken(t, next, "t2")
		expectRuns(t, h, 2)
	})

	t.Run("acts when nothing has run yet even with a cooldown", func(t *testing.T) {
		h := newHarness(func(s *config.Strategy) { s.RetryCooldown = time.Hour })

		next, err := h.provider.RefreshAfterRejection(context.Background(), &Credentials{Values: map[string]string{"token": "old"}, Version: 0})
		if err != nil {
			t.Fatal(err)
		}
		expectToken(t, next, "t1")
	})

	t.Run("propagates generator failures", func(t *testing.T) {
		h := newHarness()
		rejected := mustGet(t, h)
		h.respondFail("reauth needed")

		next, err := h.provider.RefreshAfterRejection(context.Background(), rejected)
		expectErrContains(t, err, "reauth needed")
		if next != nil {
			t.Errorf("next = %v", next)
		}
	})

	t.Run("returns nil for a nil rejected credential", func(t *testing.T) {
		h := newHarness()
		next, err := h.provider.RefreshAfterRejection(context.Background(), nil)
		if next != nil || err != nil {
			t.Errorf("got %v, %v", next, err)
		}
		expectRuns(t, h, 0)
	})

	t.Run("a waiter stops waiting when its own context ends", func(t *testing.T) {
		h := newHarness()
		rejected := mustGet(t, h)
		g := h.block()
		ctx, cancel := context.WithCancel(context.Background())

		rejection := goRefreshAfterRejection(h.provider, ctx, rejected)
		g.waitStarted(t)
		cancel()

		if r := receive(t, rejection); !errors.Is(r.err, context.Canceled) {
			t.Errorf("err = %v, want context.Canceled", r.err)
		}
		g.open(output("late", 100), nil)
	})
}

func TestStatus(t *testing.T) {
	t.Run("is empty before the first run", func(t *testing.T) {
		raw, err := json.Marshal(newHarness().provider.Status())
		if err != nil {
			t.Fatal(err)
		}
		want := `{"hasCredentials":false,"expiresAt":null,"expirySource":null,"lastRefreshedAt":null,"lastError":null}`
		if string(raw) != want {
			t.Errorf("status JSON = %s, want %s", raw, want)
		}
	})

	t.Run("reports expiry without exposing credentials", func(t *testing.T) {
		h := newHarness()
		h.respondWith(output("secret-token-1", 100))
		mustGet(t, h)

		status := h.provider.Status()
		if !status.HasCredentials || status.ExpirySource == nil || *status.ExpirySource != "output" {
			t.Errorf("status = %+v", status)
		}
		if status.ExpiresAt == nil || !status.ExpiresAt.Equal(clockStart.Add(100*time.Second)) {
			t.Errorf("ExpiresAt = %v", status.ExpiresAt)
		}
		raw, err := json.Marshal(status)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(raw), "secret-token-1") {
			t.Errorf("status JSON leaks a value: %s", raw)
		}
	})

	t.Run("serialises timestamps like toISOString", func(t *testing.T) {
		h := newHarness()
		mustGet(t, h)

		raw, err := json.Marshal(h.provider.Status())
		if err != nil {
			t.Fatal(err)
		}
		want := `{"hasCredentials":true,"expiresAt":"2023-11-14T22:15:00.000Z","expirySource":"output","lastRefreshedAt":"2023-11-14T22:13:20.000Z","lastError":null}`
		if string(raw) != want {
			t.Errorf("status JSON = %s, want %s", raw, want)
		}
	})

	t.Run("keeps credentials and reports the last error after a failed refresh", func(t *testing.T) {
		h := newHarness()
		mustGet(t, h)
		h.respondFail("later failure")
		h.clock.advance(95)
		mustGet(t, h)

		raw, err := json.Marshal(h.provider.Status())
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(raw), `"hasCredentials":true`) || !strings.Contains(string(raw), `"lastError":"later failure"`) {
			t.Errorf("status JSON = %s", raw)
		}
	})

	t.Run("the returned status is a snapshot", func(t *testing.T) {
		h := newHarness()
		mustGet(t, h)
		status := h.provider.Status()
		*status.ExpirySource = "changed"
		if got := *h.provider.Status().ExpirySource; got != "output" {
			t.Errorf("ExpirySource = %q", got)
		}
	})
}

func TestSameValues(t *testing.T) {
	tests := []struct {
		name string
		a, b map[string]string
		want bool
	}{
		{"both nil", nil, nil, true},
		{"nil and empty", nil, map[string]string{}, true},
		{"equal", map[string]string{"a": "1", "b": "2"}, map[string]string{"b": "2", "a": "1"}, true},
		{"different value", map[string]string{"a": "1"}, map[string]string{"a": "2"}, false},
		{"different name", map[string]string{"a": "1"}, map[string]string{"b": "1"}, false},
		{"subset", map[string]string{"a": "1"}, map[string]string{"a": "1", "b": "2"}, false},
		{"superset", map[string]string{"a": "1", "b": "2"}, map[string]string{"a": "1"}, false},
		{"empty value versus missing name", map[string]string{"a": ""}, map[string]string{"b": ""}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := SameValues(tt.a, tt.b); got != tt.want {
				t.Errorf("SameValues = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNewProviderDefaults(t *testing.T) {
	p := NewProvider(ProviderOptions{Name: "d", Strategy: makeStrategy(func(s *config.Strategy) {
		s.Output = "token"
		s.Command = []string{"/bin/sh", "-c", "printf real-token"}
	})})

	creds, err := p.Get(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	expectToken(t, creds, "real-token")
}
