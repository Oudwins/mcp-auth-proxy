package auth

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/Oudwins/mcp-auth-proxy/internal/config"
	"github.com/Oudwins/mcp-auth-proxy/internal/logger"
)

type Credentials struct {
	Values       map[string]string
	ExpiresAt    time.Time
	ExpirySource string
	Version      int
}

type Status struct {
	HasCredentials  bool       `json:"hasCredentials"`
	ExpiresAt       *time.Time `json:"expiresAt"`
	ExpirySource    *string    `json:"expirySource"`
	LastRefreshedAt *time.Time `json:"lastRefreshedAt"`
	LastError       *string    `json:"lastError"`
}

func isoString(t time.Time) string {
	return t.UTC().Format("2006-01-02T15:04:05.000Z")
}

func isoPtr(t *time.Time) *string {
	if t == nil {
		return nil
	}
	s := isoString(*t)
	return &s
}

// MarshalJSON renders timestamps like JavaScript's toISOString (always three fractional digits).
func (s Status) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		HasCredentials  bool    `json:"hasCredentials"`
		ExpiresAt       *string `json:"expiresAt"`
		ExpirySource    *string `json:"expirySource"`
		LastRefreshedAt *string `json:"lastRefreshedAt"`
		LastError       *string `json:"lastError"`
	}{s.HasCredentials, isoPtr(s.ExpiresAt), s.ExpirySource, isoPtr(s.LastRefreshedAt), s.LastError})
}

type ProviderOptions struct {
	Name     string
	Strategy config.Strategy
	Log      logger.Logger
	Now      func() time.Time
	Run      func(ctx context.Context, s config.Strategy, rc Context) (string, error)
}

type flight struct {
	done    chan struct{}
	creds   *Credentials
	err     error
	waiters int
}

type Provider struct {
	name     string
	strategy config.Strategy
	log      logger.Logger
	now      func() time.Time
	run      func(ctx context.Context, s config.Strategy, rc Context) (string, error)

	mu              sync.Mutex
	current         *Credentials
	inflight        *flight
	version         int
	hasRun          bool
	lastRunAt       time.Time
	lastRefreshedAt *time.Time
	lastError       *string
}

func NewProvider(o ProviderOptions) *Provider {
	p := &Provider{name: o.Name, strategy: o.Strategy, log: o.Log, now: o.Now, run: o.Run}
	if p.log == nil {
		p.log = logger.Silent
	}
	if p.now == nil {
		p.now = time.Now
	}
	if p.run == nil {
		p.run = Run
	}
	return p
}

// SameValues reports whether two credential value maps hold exactly the same names and values.
func SameValues(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for name, value := range a {
		if other, ok := b[name]; !ok || other != value {
			return false
		}
	}
	return true
}

// Get returns cached credentials, refreshing them when they are within RefreshSkew of expiry. The
// returned credentials are shared with other callers and must not be modified.
func (p *Provider) Get(ctx context.Context) (*Credentials, error) {
	p.mu.Lock()
	current := p.current
	if current != nil && p.now().Before(current.ExpiresAt.Add(-p.strategy.RefreshSkew)) {
		p.mu.Unlock()
		return current, nil
	}
	f := p.inflight
	if f == nil {
		f = p.startLocked(ctx, false)
	}
	f.waiters++
	p.mu.Unlock()

	creds, err := p.await(ctx, f)
	if err == nil {
		return creds, nil
	}
	if ctxErr := ctx.Err(); ctxErr != nil && errors.Is(err, ctxErr) {
		return nil, err
	}
	if current != nil && p.now().Before(current.ExpiresAt) {
		p.log.Warn("[%s] refresh failed, reusing credentials until they expire", p.name)
		return current, nil
	}
	return nil, err
}

// RefreshAfterRejection regenerates credentials after the upstream rejected them. It returns
// (nil, nil) when the request should not be retried.
func (p *Provider) RefreshAfterRejection(ctx context.Context, rejected *Credentials) (*Credentials, error) {
	if rejected == nil {
		return nil, nil
	}
	p.mu.Lock()
	if p.inflight != nil {
		f := p.inflight
		f.waiters++
		p.mu.Unlock()
		next, err := p.await(ctx, f)
		if ctxErr := ctx.Err(); ctxErr != nil && errors.Is(err, ctxErr) {
			return nil, err
		}
		if err != nil || next.Version == rejected.Version {
			return nil, nil
		}
		return next, nil
	}
	if current := p.current; current != nil && current.Version != rejected.Version {
		p.mu.Unlock()
		return current, nil
	}
	if sinceLastRun := p.now().Sub(p.lastRunAt); p.hasRun && sinceLastRun < p.strategy.RetryCooldown {
		p.mu.Unlock()
		p.log.Debug("[%s] rejection ignored, credentials were generated %dms ago", p.name, sinceLastRun.Milliseconds())
		return nil, nil
	}
	f := p.startLocked(ctx, true)
	f.waiters++
	p.mu.Unlock()

	next, err := p.await(ctx, f)
	if err != nil {
		return nil, err
	}
	if SameValues(next.Values, rejected.Values) {
		return nil, nil
	}
	return next, nil
}

func (p *Provider) Status() Status {
	p.mu.Lock()
	defer p.mu.Unlock()
	var s Status
	if p.current != nil {
		expiresAt, source := p.current.ExpiresAt, p.current.ExpirySource
		s.HasCredentials, s.ExpiresAt, s.ExpirySource = true, &expiresAt, &source
	}
	if p.lastRefreshedAt != nil {
		refreshedAt := *p.lastRefreshedAt
		s.LastRefreshedAt = &refreshedAt
	}
	if p.lastError != nil {
		lastError := *p.lastError
		s.LastError = &lastError
	}
	return s
}

func (p *Provider) await(ctx context.Context, f *flight) (*Credentials, error) {
	select {
	case <-f.done:
		return f.creds, f.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (p *Provider) startLocked(ctx context.Context, forced bool) *flight {
	f := &flight{done: make(chan struct{})}
	p.inflight = f
	startedAt := p.now()
	p.hasRun, p.lastRunAt = true, startedAt
	go p.generate(context.WithoutCancel(ctx), f, forced, startedAt)
	return f
}

func (p *Provider) generate(ctx context.Context, f *flight, forced bool, startedAt time.Time) {
	if p.strategy.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, p.strategy.Timeout)
		defer cancel()
	}
	creds, err := p.produce(ctx, forced, startedAt)

	p.mu.Lock()
	p.inflight = nil
	p.mu.Unlock()
	f.creds, f.err = creds, err
	close(f.done)
}

func (p *Provider) produce(ctx context.Context, forced bool, startedAt time.Time) (*Credentials, error) {
	stdout, err := p.run(ctx, p.strategy, Context{Strategy: p.name, Forced: forced})
	var parsed Parsed
	if err == nil {
		parsed, err = ParseOutput(stdout, p.strategy.Output, p.strategy.TTL, p.now())
	}
	if err != nil {
		message := err.Error()
		p.mu.Lock()
		p.lastError = &message
		p.mu.Unlock()
		p.log.Error("[%s] %s", p.name, message)
		return nil, err
	}

	refreshedAt := p.now()
	p.mu.Lock()
	p.version++
	creds := &Credentials{
		Values:       parsed.Values,
		ExpiresAt:    parsed.ExpiresAt,
		ExpirySource: parsed.ExpirySource,
		Version:      p.version,
	}
	p.current = creds
	p.lastError = nil
	p.lastRefreshedAt = &refreshedAt
	p.mu.Unlock()

	why := "expiring"
	switch {
	case forced:
		why = "after upstream rejection"
	case creds.Version == 1:
		why = "initial"
	}
	p.log.Info("[%s] credentials refreshed (%s); valid until %s via %s; took %dms",
		p.name, why, isoString(creds.ExpiresAt), creds.ExpirySource, refreshedAt.Sub(startedAt).Milliseconds())
	return creds, nil
}
