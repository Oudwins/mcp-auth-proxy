package bridge

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/Oudwins/mcp-auth-proxy/internal/logger"
)

const (
	errCodeBridge  = -32000
	maxErrBody     = 512
	maxErrRead     = 64 << 10
	getRetryDelay  = time.Second
	getMaxFailures = 5
	getStopWait    = 2 * time.Second
	deleteTimeout  = 5 * time.Second
)

type Options struct {
	Client   *http.Client
	URL      string
	Strategy string
	Target   string
	Headers  http.Header
	In       io.Reader
	Out      io.Writer
	Log      logger.Logger
}

type envelope struct {
	ID     json.RawMessage `json:"id"`
	Method string          `json:"method"`
	Result json.RawMessage `json:"result"`
}

func (e envelope) isRequest() bool {
	return e.Method != "" && len(e.ID) > 0 && string(e.ID) != "null"
}

type streamResult struct {
	delivered bool
	events    int
	lastID    string
}

type bridge struct {
	o      Options
	client *http.Client
	log    logger.Logger

	outMu sync.Mutex

	stateMu         sync.Mutex
	sessionID       string
	protocolVersion string

	getOnce sync.Once
	getCtx  context.Context
	getWG   sync.WaitGroup
}

func Run(ctx context.Context, o Options) error {
	b := &bridge{o: o, client: o.Client, log: o.Log}
	if b.client == nil {
		b.client = http.DefaultClient
	}
	if b.log == nil {
		b.log = logger.Silent
	}
	getCtx, cancelGet := context.WithCancel(ctx)
	defer cancelGet()
	b.getCtx = getCtx

	type readResult struct {
		line []byte
		err  error
	}
	lines := make(chan readResult)
	stop := make(chan struct{})
	defer close(stop)

	// Blocked reads on In cannot be interrupted, so reading happens off the main loop.
	go func() {
		r := bufio.NewReader(o.In)
		for {
			line, err := r.ReadBytes('\n')
			if line = bytes.TrimSpace(line); len(line) > 0 {
				select {
				case lines <- readResult{line: line}:
				case <-stop:
					return
				}
			}
			if err != nil {
				select {
				case lines <- readResult{err: err}:
				case <-stop:
				}
				return
			}
		}
	}()

	var (
		wg      sync.WaitGroup
		readErr error
	)
loop:
	for {
		select {
		case <-ctx.Done():
			break loop
		case rr := <-lines:
			if rr.err != nil {
				if !errors.Is(rr.err, io.EOF) {
					readErr = rr.err
				}
				break loop
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				b.handle(ctx, rr.line)
			}()
		}
	}

	wg.Wait()
	cancelGet()
	getDone := make(chan struct{})
	go func() {
		b.getWG.Wait()
		close(getDone)
	}()
	select {
	case <-getDone:
	case <-time.After(getStopWait):
		b.log.Warn("bridge: GET stream did not stop in time")
	}

	b.deleteSession(ctx)
	return readErr
}

func (b *bridge) handle(ctx context.Context, line []byte) {
	var env envelope
	_ = json.Unmarshal(line, &env)
	if b.post(ctx, line, env) && env.Method == "notifications/initialized" {
		b.startGet()
	}
}

func (b *bridge) post(ctx context.Context, line []byte, env envelope) bool {
	req, err := b.newRequest(ctx, http.MethodPost, bytes.NewReader(line), "application/json", "application/json, text/event-stream")
	if err != nil {
		b.fail(ctx, env, err.Error())
		return false
	}
	resp, err := b.client.Do(req)
	if err != nil {
		b.fail(ctx, env, "request failed: "+logger.Redact(err.Error()))
		return false
	}
	defer resp.Body.Close()
	b.captureSession(resp)

	switch resp.StatusCode {
	case http.StatusAccepted, http.StatusNoContent:
		return true
	case http.StatusOK:
		ct := mediaType(resp)
		switch ct {
		case "application/json":
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				b.fail(ctx, env, "reading response: "+logger.Redact(err.Error()))
				return false
			}
			ok, answered := b.deliver(body, env)
			switch {
			case !ok:
				b.fail(ctx, env, "response body was not valid JSON")
			case env.isRequest() && !answered:
				b.fail(ctx, env, "response did not answer the request")
			}
			return true
		case "text/event-stream":
			res, err := b.forward(resp.Body, env)
			if env.isRequest() && !res.delivered {
				msg := "stream ended before a response was received"
				if err != nil {
					msg = "stream error: " + logger.Redact(err.Error())
				}
				b.fail(ctx, env, msg)
			} else if err != nil && ctx.Err() == nil {
				b.log.Warn("bridge: stream error: %s", logger.Redact(err.Error()))
			}
			return true
		default:
			b.fail(ctx, env, fmt.Sprintf("HTTP 200: unexpected content type %q", ct))
			return false
		}
	default:
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrRead))
		b.fail(ctx, env, httpErrText(resp.StatusCode, body))
		return false
	}
}

func (b *bridge) forward(body io.Reader, env envelope) (streamResult, error) {
	var res streamResult
	err := readSSE(body, func(ev sseEvent) {
		if ev.ID != "" {
			res.lastID = ev.ID
		}
		if ev.Data == "" || (ev.Event != "" && ev.Event != "message") {
			return
		}
		res.events++
		if _, answered := b.deliver([]byte(ev.Data), env); answered {
			res.delivered = true
		}
	})
	return res, err
}

// deliver reports whether data was written and whether it answers the request in env.
func (b *bridge) deliver(data []byte, env envelope) (written, answered bool) {
	if !b.writeLine(data) {
		return false, false
	}
	if !env.isRequest() || !answers(data, env.ID) {
		return true, false
	}
	if env.Method == "initialize" {
		if v := protocolVersionOf(data); v != "" {
			b.stateMu.Lock()
			b.protocolVersion = v
			b.stateMu.Unlock()
		}
	}
	return true, true
}

func (b *bridge) writeLine(data []byte) bool {
	var buf bytes.Buffer
	if err := json.Compact(&buf, data); err != nil {
		b.log.Warn("bridge: dropping payload that is not valid JSON: %v", err)
		return false
	}
	buf.WriteByte('\n')
	b.outMu.Lock()
	defer b.outMu.Unlock()
	if _, err := b.o.Out.Write(buf.Bytes()); err != nil {
		b.log.Warn("bridge: writing to output failed: %v", err)
		return false
	}
	return true
}

func (b *bridge) fail(ctx context.Context, env envelope, msg string) {
	if ctx.Err() != nil {
		return
	}
	if !env.isRequest() {
		b.log.Warn("bridge: %s failed: %s", env.Method, msg)
		return
	}
	payload, err := json.Marshal(struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      json.RawMessage `json:"id"`
		Error   struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}{
		JSONRPC: "2.0",
		ID:      env.ID,
		Error: struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		}{errCodeBridge, msg},
	})
	if err != nil {
		b.log.Error("bridge: encoding error response: %v", err)
		return
	}
	b.log.Warn("bridge: %s failed: %s", env.Method, msg)
	b.writeLine(payload)
}

func (b *bridge) newRequest(ctx context.Context, method string, body io.Reader, contentType, accept string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, b.o.URL, body)
	if err != nil {
		return nil, fmt.Errorf("building request: %w", err)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	if b.o.Strategy != "" {
		req.Header.Set("X-Proxy-Strategy", b.o.Strategy)
	}
	if b.o.Target != "" {
		req.Header.Set("X-Proxy-Target", b.o.Target)
	}
	for k, vs := range b.o.Headers {
		req.Header.Del(k)
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	b.stateMu.Lock()
	if b.sessionID != "" {
		req.Header.Set("Mcp-Session-Id", b.sessionID)
	}
	if b.protocolVersion != "" {
		req.Header.Set("MCP-Protocol-Version", b.protocolVersion)
	}
	b.stateMu.Unlock()
	return req, nil
}

func (b *bridge) captureSession(resp *http.Response) {
	if id := resp.Header.Get("Mcp-Session-Id"); id != "" {
		b.stateMu.Lock()
		b.sessionID = id
		b.stateMu.Unlock()
	}
}

func (b *bridge) startGet() {
	b.getOnce.Do(func() {
		b.getWG.Add(1)
		go func() {
			defer b.getWG.Done()
			b.runGet(b.getCtx)
		}()
	})
}

func (b *bridge) runGet(ctx context.Context) {
	failures := 0
	lastID := ""
	for {
		status, res, err := b.openGet(ctx, lastID)
		if ctx.Err() != nil {
			return
		}
		if err == nil && status != http.StatusOK {
			b.log.Debug("bridge: GET stream not available (HTTP %d)", status)
			return
		}
		if res.lastID != "" {
			lastID = res.lastID
		}
		if err != nil || res.events == 0 {
			failures++
			if err != nil {
				b.log.Debug("bridge: GET stream failed: %s", logger.Redact(err.Error()))
			}
			if failures >= getMaxFailures {
				b.log.Warn("bridge: giving up on GET stream after %d consecutive failures", failures)
				return
			}
		} else {
			failures = 0
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(getRetryDelay):
		}
	}
}

func (b *bridge) openGet(ctx context.Context, lastID string) (int, streamResult, error) {
	req, err := b.newRequest(ctx, http.MethodGet, nil, "", "text/event-stream")
	if err != nil {
		return 0, streamResult{}, err
	}
	if lastID != "" {
		req.Header.Set("Last-Event-ID", lastID)
	}
	resp, err := b.client.Do(req)
	if err != nil {
		return 0, streamResult{}, err
	}
	defer resp.Body.Close()
	b.captureSession(resp)
	if resp.StatusCode != http.StatusOK {
		return resp.StatusCode, streamResult{}, nil
	}
	if ct := mediaType(resp); ct != "text/event-stream" {
		return resp.StatusCode, streamResult{}, fmt.Errorf("unexpected content type %q", ct)
	}
	res, err := b.forward(resp.Body, envelope{})
	return resp.StatusCode, res, err
}

func (b *bridge) deleteSession(ctx context.Context) {
	b.stateMu.Lock()
	id := b.sessionID
	b.stateMu.Unlock()
	if id == "" {
		return
	}
	dctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), deleteTimeout)
	defer cancel()
	req, err := b.newRequest(dctx, http.MethodDelete, nil, "", "")
	if err != nil {
		return
	}
	resp, err := b.client.Do(req)
	if err != nil {
		b.log.Debug("bridge: session DELETE failed: %s", logger.Redact(err.Error()))
		return
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxErrRead))
	resp.Body.Close()
}

func mediaType(resp *http.Response) string {
	mt, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil {
		return strings.ToLower(strings.TrimSpace(resp.Header.Get("Content-Type")))
	}
	return mt
}

func answers(payload []byte, id json.RawMessage) bool {
	var one envelope
	if json.Unmarshal(payload, &one) == nil {
		return one.Method == "" && bytes.Equal(one.ID, id)
	}
	var batch []envelope
	if json.Unmarshal(payload, &batch) == nil {
		for _, e := range batch {
			if e.Method == "" && bytes.Equal(e.ID, id) {
				return true
			}
		}
	}
	return false
}

func protocolVersionOf(payload []byte) string {
	var batch []envelope
	if json.Unmarshal(payload, &batch) != nil {
		var one envelope
		if json.Unmarshal(payload, &one) != nil {
			return ""
		}
		batch = []envelope{one}
	}
	for _, e := range batch {
		var res struct {
			ProtocolVersion string `json:"protocolVersion"`
		}
		if json.Unmarshal(e.Result, &res) == nil && res.ProtocolVersion != "" {
			return res.ProtocolVersion
		}
	}
	return ""
}

func httpErrText(status int, body []byte) string {
	var shaped struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	var detail string
	if json.Unmarshal(body, &shaped) == nil && shaped.Error.Message != "" {
		detail = shaped.Error.Message
		if shaped.Error.Code != "" {
			detail = shaped.Error.Code + ": " + detail
		}
	} else {
		detail = string(bytes.TrimSpace(body))
	}
	detail = truncate(logger.Redact(detail), maxErrBody)
	text := fmt.Sprintf("HTTP %d", status)
	if detail != "" {
		text += ": " + detail
	}
	return text
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}
