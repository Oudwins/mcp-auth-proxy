package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/Oudwins/mcp-auth-proxy/internal/auth"
	"github.com/Oudwins/mcp-auth-proxy/internal/config"
	"github.com/Oudwins/mcp-auth-proxy/internal/headers"
	"github.com/Oudwins/mcp-auth-proxy/internal/hosts"
	"github.com/Oudwins/mcp-auth-proxy/internal/logger"
	"github.com/Oudwins/mcp-auth-proxy/internal/template"
)

const (
	healthPath        = "/_health"
	maxRetryDrain     = 64 * 1024
	relayBufferSize   = 32 * 1024
	dialTimeout       = 30 * time.Second
	idleConnTimeout   = 90 * time.Second
	tlsHandshakeLimit = 10 * time.Second
)

var loopbackHosts = []string{"127.0.0.1", "localhost", "::1"}

type Options struct {
	Config *config.Config
	Log    logger.Logger
}

type Running struct {
	Host      string
	Port      int
	URL       string
	Providers map[string]*auth.Provider

	server    *http.Server
	transport *http.Transport
}

type strategy struct {
	name          string
	provider      *auth.Provider
	retryOnStatus []int
	allowedHosts  []string
	rules         []hosts.Rule
}

type handler struct {
	cfg        *config.Config
	log        logger.Logger
	strategies map[string]*strategy
	names      []string
	proxyHosts map[string]bool
	transport  *http.Transport
}

type requestState struct {
	label string
	host  string
}

type clientGoneError struct{ err error }

func (e clientGoneError) Error() string { return e.err.Error() }

func bracketed(host string) string {
	if strings.Contains(host, ":") {
		return "[" + host + "]"
	}
	return host
}

func Start(o Options) (*Running, error) {
	cfg := o.Config
	if cfg == nil {
		return nil, errors.New("proxy: missing config")
	}
	log := o.Log
	if log == nil {
		log = logger.Silent
	}

	transport := &http.Transport{
		Proxy:               nil,
		DisableCompression:  true,
		DialContext:         (&net.Dialer{Timeout: dialTimeout, KeepAlive: dialTimeout}).DialContext,
		MaxIdleConns:        100,
		IdleConnTimeout:     idleConnTimeout,
		TLSHandshakeTimeout: tlsHandshakeLimit,
	}
	h := &handler{
		cfg:        cfg,
		log:        log,
		strategies: make(map[string]*strategy, len(cfg.Strategies)),
		names:      cfg.StrategyNames(),
		transport:  transport,
	}
	providers := make(map[string]*auth.Provider, len(cfg.Strategies))
	for name, s := range cfg.Strategies {
		rules, err := hosts.Compile(s.AllowedHosts)
		if err != nil {
			return nil, fmt.Errorf("strategy %q: %w", name, err)
		}
		provider := auth.NewProvider(auth.ProviderOptions{Name: name, Strategy: s, Log: log})
		providers[name] = provider
		h.strategies[name] = &strategy{
			name:          name,
			provider:      provider,
			retryOnStatus: s.RetryOnStatus,
			allowedHosts:  s.AllowedHosts,
			rules:         rules,
		}
	}

	host := cfg.Listen.Host
	listener, err := net.Listen("tcp", net.JoinHostPort(host, strconv.Itoa(cfg.Listen.Port)))
	if err != nil {
		return nil, err
	}
	port := listener.Addr().(*net.TCPAddr).Port

	h.proxyHosts = make(map[string]bool)
	for _, name := range append([]string{host}, loopbackHosts...) {
		h.proxyHosts[strings.ToLower(bracketed(name)+":"+strconv.Itoa(port))] = true
	}
	if !slices.Contains(loopbackHosts, host) {
		log.Warn("listening on non-loopback address %s; anything that can reach it can use your credentials", host)
	}

	server := &http.Server{Handler: h}
	go func() {
		if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("server stopped unexpectedly: %v", err)
		}
	}()

	return &Running{
		Host:      host,
		Port:      port,
		URL:       "http://" + bracketed(host) + ":" + strconv.Itoa(port) + "/",
		Providers: providers,
		server:    server,
		transport: transport,
	}, nil
}

// Close stops accepting connections and waits for in-flight requests until ctx ends, then closes
// whatever is left. Hitting the ctx deadline is not reported as an error.
func (r *Running) Close(ctx context.Context) error {
	err := r.server.Shutdown(ctx)
	if err != nil {
		_ = r.server.Close()
	}
	r.transport.CloseIdleConnections()
	if err != nil && ctx.Err() != nil && errors.Is(err, ctx.Err()) {
		return nil
	}
	return err
}

type trackingWriter struct {
	http.ResponseWriter
	wrote bool
}

func (t *trackingWriter) WriteHeader(code int) {
	t.wrote = true
	t.ResponseWriter.WriteHeader(code)
}

func (t *trackingWriter) Write(b []byte) (int, error) {
	t.wrote = true
	return t.ResponseWriter.Write(b)
}

func (t *trackingWriter) Unwrap() http.ResponseWriter { return t.ResponseWriter }

func sendJSON(w http.ResponseWriter, status int, body any) {
	var buf bytes.Buffer
	encoder := json.NewEncoder(&buf)
	encoder.SetEscapeHTML(false)
	_ = encoder.Encode(body)
	payload := bytes.TrimRight(buf.Bytes(), "\n")
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", strconv.Itoa(len(payload)))
	w.WriteHeader(status)
	_, _ = w.Write(payload)
}

type errorBody struct {
	Error errorDetail `json:"error"`
}

type errorDetail struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func sendError(w http.ResponseWriter, status int, code, message string) {
	sendJSON(w, status, errorBody{Error: errorDetail{Code: code, Message: message}})
}

func (h *handler) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	w := &trackingWriter{ResponseWriter: rw}
	defer func() {
		rec := recover()
		if rec == nil {
			return
		}
		if rec == http.ErrAbortHandler {
			panic(rec)
		}
		h.log.Error("unexpected error: %v", rec)
		if w.wrote {
			panic(http.ErrAbortHandler)
		}
		sendError(w, http.StatusInternalServerError, "internal_error", "unexpected proxy error")
	}()

	if !h.proxyHosts[strings.ToLower(r.Host)] {
		sendError(w, http.StatusForbidden, "forbidden_host", "Host header is not a loopback address of this proxy")
		return
	}
	if _, ok := r.Header["Origin"]; ok {
		sendError(w, http.StatusForbidden, "forbidden_origin", "requests carrying an Origin header (browsers) are not allowed")
		return
	}
	if r.URL.Path == healthPath {
		h.health(w)
		return
	}

	state := &requestState{label: "proxy"}
	if err := h.proxyRequest(w, r, state); err != nil {
		h.fail(w, r, state, err)
	}
}

type healthStrategy struct {
	AllowedHosts []string    `json:"allowedHosts"`
	Auth         auth.Status `json:"auth"`
}

type healthReport struct {
	OK         bool                      `json:"ok"`
	Strategies map[string]healthStrategy `json:"strategies"`
}

func (h *handler) health(w http.ResponseWriter) {
	report := healthReport{OK: true, Strategies: make(map[string]healthStrategy, len(h.strategies))}
	for name, s := range h.strategies {
		report.Strategies[name] = healthStrategy{
			AllowedHosts: append([]string{}, s.allowedHosts...),
			Auth:         s.provider.Status(),
		}
	}
	sendJSON(w, http.StatusOK, report)
}

func (h *handler) fail(w *trackingWriter, r *http.Request, state *requestState, err error) {
	var gone clientGoneError
	if r.Context().Err() != nil || errors.As(err, &gone) {
		return
	}
	if w.wrote {
		h.log.Warn("[%s] stream ended abnormally: %s", state.label, logger.Redact(err.Error()))
		panic(http.ErrAbortHandler)
	}

	var (
		reqErr      *requestError
		placeholder *template.PlaceholderError
		tooLarge    *http.MaxBytesError
		command     *auth.CommandError
	)
	switch {
	case errors.As(err, &reqErr):
		sendError(w, reqErr.status, reqErr.code, reqErr.message)
	case errors.As(err, &placeholder):
		sendError(w, http.StatusBadRequest, "unknown_placeholder", placeholder.Error())
	case errors.As(err, &tooLarge):
		sendError(w, http.StatusRequestEntityTooLarge, "body_too_large",
			fmt.Sprintf("request body exceeds %d bytes", h.cfg.MaxBodyBytes))
	case errors.As(err, &command):
		sendError(w, http.StatusBadGateway, "auth_command_failed", fmt.Sprintf("[%s] %s", state.label, command.Message))
	default:
		message := logger.Redact(err.Error())
		h.log.Error("[%s] upstream request failed: %s", state.label, message)
		sendError(w, http.StatusBadGateway, "upstream_unreachable", fmt.Sprintf("cannot reach %s: %s", state.host, message))
	}
}

func (h *handler) proxyRequest(w *trackingWriter, r *http.Request, state *requestState) error {
	started := time.Now()
	ctx := r.Context()

	name := headerValue(r.Header, strategyHeader)
	if name == "" {
		return &requestError{http.StatusBadRequest, "missing_strategy",
			fmt.Sprintf("set the %s header; available: %s", strings.ToLower(strategyHeader), strings.Join(h.names, ", "))}
	}
	strat, ok := h.strategies[name]
	if !ok {
		return &requestError{http.StatusBadRequest, "unknown_strategy",
			fmt.Sprintf("no strategy named %q; available: %s", name, strings.Join(h.names, ", "))}
	}
	state.label = strat.name

	rawTarget := headerValue(r.Header, targetHeader)
	if rawTarget == "" {
		return &requestError{http.StatusBadRequest, "missing_target",
			fmt.Sprintf("set the %s header to the URL to proxy to", strings.ToLower(targetHeader))}
	}
	tpl, err := parseTarget(rawTarget)
	if err != nil {
		return err
	}
	state.host = tpl.authority

	origin, err := tpl.originURL()
	if err != nil {
		return err
	}
	if !hosts.Allowed(strat.rules, origin) {
		return &requestError{http.StatusForbidden, "target_not_allowed",
			fmt.Sprintf("%s://%s is not in the allowedHosts of strategy %q (%s)",
				tpl.scheme, tpl.authority, strat.name, strings.Join(strat.allowedHosts, ", "))}
	}

	body, err := io.ReadAll(http.MaxBytesReader(w.ResponseWriter, r.Body, h.cfg.MaxBodyBytes))
	if err != nil {
		return err
	}

	if !usesPlaceholders(r.Header, tpl) {
		return &requestError{http.StatusBadRequest, "no_placeholder",
			"no {{placeholder}} found in the target path/query or any header, so the credential would never be sent"}
	}

	sfx := suffix{path: r.URL.EscapedPath(), query: r.URL.RawQuery}
	if sfx.path == "/" {
		sfx.path = ""
	}

	creds, err := strat.provider.Get(ctx)
	if err != nil {
		return err
	}
	resp, err := h.send(ctx, r, tpl, sfx, body, creds.Values)
	if err != nil {
		return err
	}
	retried := false

	if slices.Contains(strat.retryOnStatus, resp.StatusCode) {
		fresh, err := strat.provider.RefreshAfterRejection(ctx, creds)
		if err != nil {
			discard(resp)
			return err
		}
		if fresh != nil {
			h.log.Info("[%s] upstream answered %d; retrying once with fresh credentials", strat.name, resp.StatusCode)
			discard(resp)
			retried = true
			resp, err = h.send(ctx, r, tpl, sfx, body, fresh.Values)
			if err != nil {
				return err
			}
		}
	}
	defer resp.Body.Close()

	note := ""
	if retried {
		note = " (retried)"
	}
	h.log.Debug("[%s] %s %s%s -> %d in %dms%s",
		strat.name, r.Method, tpl.authority, tpl.path, resp.StatusCode, time.Since(started).Milliseconds(), note)
	return relay(w, resp)
}

func discard(resp *http.Response) {
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxRetryDrain))
	_ = resp.Body.Close()
}

func (h *handler) send(
	ctx context.Context,
	r *http.Request,
	tpl targetTemplate,
	sfx suffix,
	body []byte,
	values map[string]string,
) (*http.Response, error) {
	target, err := buildTarget(tpl, sfx, values)
	if err != nil {
		return nil, err
	}
	header, err := forwardHeaders(r.Header, values)
	if err != nil {
		return nil, err
	}
	// An empty User-Agent value stops the transport from injecting its own.
	if _, ok := header["User-Agent"]; !ok {
		header["User-Agent"] = []string{""}
	}

	req := &http.Request{Method: r.Method, URL: target, Header: header, Host: target.Host}
	switch {
	case len(body) > 0:
		req.Body = io.NopCloser(bytes.NewReader(body))
		req.ContentLength = int64(len(body))
	case r.Method == http.MethodPost || r.Method == http.MethodPut || r.Method == http.MethodPatch:
		req.Body = http.NoBody
	}
	return h.transport.RoundTrip(req.WithContext(ctx))
}

func relay(w *trackingWriter, resp *http.Response) error {
	dst := w.Header()
	for name, values := range headers.StripHopByHop(resp.Header) {
		dst[name] = values
	}
	// A nil value stops the server from sniffing a Content-Type the upstream did not send.
	if _, ok := dst["Content-Type"]; !ok {
		dst["Content-Type"] = nil
	}
	w.WriteHeader(resp.StatusCode)
	controller := http.NewResponseController(w)
	_ = controller.Flush()

	buf := make([]byte, relayBufferSize)
	for {
		n, err := resp.Body.Read(buf)
		if n > 0 {
			if _, werr := w.Write(buf[:n]); werr != nil {
				return clientGoneError{werr}
			}
			_ = controller.Flush()
		}
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
	}
}
