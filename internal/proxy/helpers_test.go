package proxy

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Oudwins/mcp-auth-proxy/internal/config"
	"github.com/Oudwins/mcp-auth-proxy/internal/logger"
)

const (
	testAPIKey    = "test-api-key"
	mockHostToken = "$MOCK"
	omit          = "\x00omit"
)

const generatorScript = `#!/bin/sh
set -eu
: "${STATE_DIR:?STATE_DIR is required}"

if [ -e "$STATE_DIR/fail" ]; then
  echo "Reauthentication is needed: ADC credentials expired (Bearer leaked.secret-value)" >&2
  exit 1
fi

n=$(( $(cat "$STATE_DIR/count" 2>/dev/null || echo 0) + 1 ))
echo "$n" > "$STATE_DIR/count"
echo "${MCP_AUTH_PROXY_FORCE_REFRESH:-unset}" >> "$STATE_DIR/force.log"
echo "${MCP_AUTH_PROXY_STRATEGY:-unset}" > "$STATE_DIR/strategy-name"

sleep "${GEN_DELAY:-0}"

exp=$(( $(date +%s) + ${TOKEN_LIFETIME:-3600} ))
token="tok.${n}.${exp}"

case "${GEN_FORMAT:-json}" in
  token)
    echo "$token"
    ;;
  static)
    echo "tok.1.4102444800"
    ;;
  multi)
    printf '{"values":{"token":"%s","tenant":"%s"},"expiresAt":%s}\n' "$token" "${TENANT:-acme corp}" "$exp"
    ;;
  expiring)
    printf '{"values":{"token":"%s"},"expiresInSeconds":%s}\n' "$token" "${EXPIRES_IN:-2}"
    ;;
  crlf)
    printf '{"values":{"token":"%s\\r\\nX-Evil: 1"},"expiresAt":%s}\n' "$token" "$exp"
    ;;
  *)
    printf '{"values":{"token":"%s"},"expiresAt":%s}\n' "$token" "$exp"
    ;;
esac
`

type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

type seenRequest struct {
	Method        string
	URL           string
	Host          string
	Header        http.Header
	Body          []byte
	ContentLength int64
	Status        int
}

type statusRecorder struct {
	http.ResponseWriter
	record func(int)
	wrote  bool
}

func (s *statusRecorder) WriteHeader(code int) {
	if !s.wrote {
		s.wrote = true
		s.record(code)
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Write(b []byte) (int, error) {
	if !s.wrote {
		s.WriteHeader(http.StatusOK)
	}
	return s.ResponseWriter.Write(b)
}

func (s *statusRecorder) Unwrap() http.ResponseWriter { return s.ResponseWriter }

var tokenPattern = regexp.MustCompile(`^Bearer tok\.(\d+)\.(\d+)$`)

// mockUpstream stands in for an IAP-protected MCP server: every request needs a live
// "Proxy-Authorization: Bearer tok.<serial>.<exp>" (or the same value as ?access_token=).
type mockUpstream struct {
	URL string

	server   *http.Server
	sse      bool
	apiKey   string
	gzipBody []byte
	aborted  chan struct{}
	stopOnce sync.Once

	mu             sync.Mutex
	seen           []seenRequest
	revokedThrough int
	rejectAll      bool
	gate           chan struct{}
	release        func()
	sessions       map[string]bool
}

func startMockUpstream(t *testing.T, sse bool, apiKey string) *mockUpstream {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("mock upstream cannot listen: %v", err)
	}
	var zipped bytes.Buffer
	zw := gzip.NewWriter(&zipped)
	_, _ = zw.Write([]byte("hello hello hello hello"))
	_ = zw.Close()

	open := make(chan struct{})
	close(open)
	m := &mockUpstream{
		URL:      "http://" + listener.Addr().String() + "/mcp",
		sse:      sse,
		apiKey:   apiKey,
		gzipBody: zipped.Bytes(),
		aborted:  make(chan struct{}, 8),
		gate:     open,
		release:  func() {},
		sessions: map[string]bool{},
	}
	m.server = &http.Server{Handler: m}
	go func() { _ = m.server.Serve(listener) }()
	t.Cleanup(m.Close)
	return m
}

func (m *mockUpstream) Close() {
	m.stopOnce.Do(func() {
		m.mu.Lock()
		release := m.release
		m.mu.Unlock()
		release()
		_ = m.server.Close()
	})
}

func (m *mockUpstream) origin() string {
	return strings.TrimSuffix(m.URL, "/mcp")
}

func (m *mockUpstream) requests() []seenRequest {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]seenRequest, len(m.seen))
	copy(out, m.seen)
	return out
}

func (m *mockUpstream) last(t *testing.T) seenRequest {
	t.Helper()
	all := m.requests()
	if len(all) == 0 {
		t.Fatal("the upstream saw no requests")
	}
	return all[len(all)-1]
}

func (m *mockUpstream) revokeThrough(serial int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.revokedThrough = serial
}

func (m *mockUpstream) setRejectAll(value bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.rejectAll = value
}

// holdStream makes /mcp/stream wait before its second event until the returned func is called.
func (m *mockUpstream) holdStream() func() {
	m.mu.Lock()
	defer m.mu.Unlock()
	gate := make(chan struct{})
	var once sync.Once
	m.gate = gate
	m.release = func() { once.Do(func() { close(gate) }) }
	return m.release
}

func (m *mockUpstream) record(r *http.Request, body []byte) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.seen = append(m.seen, seenRequest{
		Method:        r.Method,
		URL:           r.RequestURI,
		Host:          r.Host,
		Header:        r.Header.Clone(),
		Body:          body,
		ContentLength: r.ContentLength,
	})
	return len(m.seen) - 1
}

func (m *mockUpstream) setStatus(index, status int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.seen[index].Status = status
}

func (m *mockUpstream) tokenAccepted(credential string) bool {
	match := tokenPattern.FindStringSubmatch(credential)
	m.mu.Lock()
	defer m.mu.Unlock()
	if match == nil || m.rejectAll {
		return false
	}
	serial, _ := strconv.Atoi(match[1])
	exp, _ := strconv.ParseInt(match[2], 10, 64)
	return serial > m.revokedThrough && exp*1000 > time.Now().UnixMilli()
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func (m *mockUpstream) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	index := m.record(r, body)
	w := &statusRecorder{ResponseWriter: rw, record: func(code int) { m.setStatus(index, code) }}

	credential := r.Header.Get("Proxy-Authorization")
	if credential == "" {
		if query := r.URL.Query().Get("access_token"); query != "" {
			credential = "Bearer " + query
		}
	}
	if !m.tokenAccepted(credential) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "Invalid IAP credentials"})
		return
	}
	if m.apiKey != "" && r.Header.Get("Authorization") != "Bearer "+m.apiKey {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "bad api key"})
		return
	}

	switch path := r.URL.Path; {
	case path == "/mcp/redirect":
		w.Header().Set("Location", "http://127.0.0.1:9/elsewhere")
		w.WriteHeader(http.StatusFound)
	case strings.HasPrefix(path, "/mcp/ping"):
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "body": string(body)})
	case path == "/mcp/stream":
		m.stream(w, r)
	case path == "/mcp/hop":
		w.Header().Set("Connection", "X-Resp")
		w.Header().Set("Keep-Alive", "timeout=5")
		w.Header().Set("Proxy-Authenticate", "Basic realm=x")
		w.Header().Set("X-Resp", "secret")
		w.Header().Set("X-Normal", "ok")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("hop"))
	case path == "/mcp/gzip":
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Content-Encoding", "gzip")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(m.gzipBody)
	case path == "/mcp/notype":
		w.Header()["Content-Type"] = nil
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<html><body>plain</body></html>"))
	default:
		m.mcp(w, r, body)
	}
}

func (m *mockUpstream) stream(w http.ResponseWriter, r *http.Request) {
	m.mu.Lock()
	gate := m.gate
	m.mu.Unlock()

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, "data: first\n\n")
	_ = http.NewResponseController(w).Flush()
	select {
	case <-gate:
		_, _ = io.WriteString(w, "data: second\n\n")
	case <-r.Context().Done():
		m.aborted <- struct{}{}
	}
}

type rpcMessage struct {
	JSONRPC string          `json:"jsonrpc,omitempty"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type toolContent struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

func (m *mockUpstream) reply(w http.ResponseWriter, id json.RawMessage, result any) {
	payload, _ := json.Marshal(rpcMessage{JSONRPC: "2.0", ID: id, Result: mustMarshal(result)})
	if m.sse {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "event: message\ndata: "+string(payload)+"\n\n")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(payload)
}

func mustMarshal(v any) json.RawMessage {
	out, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return out
}

func (m *mockUpstream) mcp(w http.ResponseWriter, r *http.Request, body []byte) {
	var msg rpcMessage
	if r.Method == http.MethodPost && json.Unmarshal(body, &msg) != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad json"})
		return
	}

	if r.Method == http.MethodPost && msg.Method == "initialize" {
		raw := make([]byte, 16)
		_, _ = rand.Read(raw)
		session := hex.EncodeToString(raw)
		m.mu.Lock()
		m.sessions[session] = true
		m.mu.Unlock()
		w.Header().Set("Mcp-Session-Id", session)
		m.reply(w, msg.ID, map[string]any{
			"protocolVersion": "2025-03-26",
			"capabilities":    map[string]any{"tools": map[string]any{}},
			"serverInfo":      map[string]string{"name": "mock-upstream", "version": "1.0.0"},
		})
		return
	}

	m.mu.Lock()
	known := m.sessions[r.Header.Get("Mcp-Session-Id")]
	m.mu.Unlock()
	if !known || r.Method != http.MethodPost {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "no session"})
		return
	}

	switch {
	case len(msg.ID) == 0:
		w.WriteHeader(http.StatusAccepted)
	case msg.Method == "tools/list":
		m.reply(w, msg.ID, map[string]any{"tools": []map[string]any{{
			"name":        "echo",
			"description": "Echo text back",
			"inputSchema": map[string]any{"type": "object"},
		}}})
	case msg.Method == "tools/call":
		var call struct {
			Name      string `json:"name"`
			Arguments struct {
				Text string `json:"text"`
			} `json:"arguments"`
		}
		_ = json.Unmarshal(msg.Params, &call)
		m.reply(w, msg.ID, map[string]any{"content": []toolContent{{Type: "text", Text: "echo:" + call.Arguments.Text}}})
	default:
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unsupported method"})
	}
}

type stackOptions struct {
	lifetime             int
	skew                 float64
	cooldown             float64
	genDelay             float64
	genFormat            string
	tenant               string
	expiresIn            int
	commandArray         bool
	retryOnStatus        []int
	strategyAllowedHosts []string
	globalAllowedHosts   []string
	extraStrategies      []string
	requireAPIKey        bool
	maxBodyBytes         int
	mockSSE              bool
	listenHost           string
}

type stack struct {
	t        *testing.T
	opts     stackOptions
	mock     *mockUpstream
	proxy    *Running
	logs     *syncBuffer
	stateDir string
	client   *http.Client
}

func writeGenerator(t *testing.T) (dir, script string) {
	t.Helper()
	dir = t.TempDir()
	script = filepath.Join(dir, "gen.sh")
	if err := os.WriteFile(script, []byte(generatorScript), 0o755); err != nil {
		t.Fatalf("cannot write generator: %v", err)
	}
	return dir, script
}

func buildConfig(t *testing.T, o stackOptions, mockOrigin string) *config.Config {
	t.Helper()
	dir, script := writeGenerator(t)
	stateDir := filepath.Join(dir, "state")
	if err := os.MkdirAll(stateDir, 0o755); err != nil {
		t.Fatal(err)
	}

	resolve := func(entries []string) []any {
		out := make([]any, len(entries))
		for i, entry := range entries {
			out[i] = entry
			if entry == mockHostToken {
				out[i] = mockOrigin
			}
		}
		return out
	}
	lifetime := o.lifetime
	if lifetime == 0 {
		lifetime = 3600
	}
	skew := o.skew
	if skew == 0 {
		skew = 1
	}
	format := o.genFormat
	if format == "" {
		format = "json"
	}
	output := "json"
	if format == "token" || format == "static" {
		output = "token"
	}
	env := map[string]any{
		"STATE_DIR":      stateDir,
		"TOKEN_LIFETIME": strconv.Itoa(lifetime),
		"GEN_DELAY":      strconv.FormatFloat(o.genDelay, 'f', -1, 64),
		"GEN_FORMAT":     format,
	}
	if o.tenant != "" {
		env["TENANT"] = o.tenant
	}
	if o.expiresIn != 0 {
		env["EXPIRES_IN"] = strconv.Itoa(o.expiresIn)
	}

	up := map[string]any{
		"command":       "sh " + script,
		"output":        output,
		"ttl":           float64(lifetime),
		"refreshSkew":   skew,
		"retryCooldown": o.cooldown,
		"env":           env,
	}
	if o.commandArray {
		up["command"] = []any{"sh", script}
	}
	if o.retryOnStatus != nil {
		codes := make([]any, len(o.retryOnStatus))
		for i, code := range o.retryOnStatus {
			codes[i] = code
		}
		up["retryOnStatus"] = codes
	}
	if o.strategyAllowedHosts != nil {
		up["allowedHosts"] = resolve(o.strategyAllowedHosts)
	}
	strategies := map[string]any{"up": up}
	for _, name := range o.extraStrategies {
		strategies[name] = up
	}

	global := o.globalAllowedHosts
	if global == nil {
		global = []string{mockHostToken}
	}
	raw := map[string]any{
		"listen":       map[string]any{"port": 0},
		"allowedHosts": resolve(global),
		"strategies":   strategies,
	}
	if o.listenHost != "" {
		raw["listen"] = map[string]any{"host": o.listenHost, "port": 0}
	}
	if o.maxBodyBytes > 0 {
		raw["maxBodyBytes"] = o.maxBodyBytes
	}
	cfg, err := config.Parse(raw, dir)
	if err != nil {
		t.Fatalf("test config is invalid: %v", err)
	}
	return cfg
}

func startStack(t *testing.T, o stackOptions) *stack {
	t.Helper()
	apiKey := ""
	if o.requireAPIKey {
		apiKey = testAPIKey
	}
	mock := startMockUpstream(t, o.mockSSE, apiKey)
	logs := &syncBuffer{}
	cfg := buildConfig(t, o, mock.origin())
	running, err := Start(Options{Config: cfg, Log: logger.New(true, logs)})
	if err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		defer cancel()
		_ = running.Close(ctx)
	})

	return &stack{
		t:        t,
		opts:     o,
		mock:     mock,
		proxy:    running,
		logs:     logs,
		stateDir: cfg.Strategies["up"].Env["STATE_DIR"],
		client: &http.Client{
			Timeout: 15 * time.Second,
			Transport: &http.Transport{
				Proxy:              nil,
				DisableCompression: true,
				DisableKeepAlives:  true,
			},
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}
}

func (s *stack) readState(file string) string {
	data, err := os.ReadFile(filepath.Join(s.stateDir, file))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func (s *stack) generatorRuns() int {
	n, _ := strconv.Atoi(s.readState("count"))
	return n
}

func (s *stack) forceFlags() []string {
	text := s.readState("force.log")
	if text == "" {
		return nil
	}
	return strings.Split(text, "\n")
}

func (s *stack) strategyName() string { return s.readState("strategy-name") }

func (s *stack) makeGeneratorFail() {
	s.t.Helper()
	if err := os.WriteFile(filepath.Join(s.stateDir, "fail"), nil, 0o644); err != nil {
		s.t.Fatal(err)
	}
}

func (s *stack) makeGeneratorSucceed() {
	s.t.Helper()
	if err := os.Remove(filepath.Join(s.stateDir, "fail")); err != nil && !os.IsNotExist(err) {
		s.t.Fatal(err)
	}
}

// H holds header overrides; the value omit drops a header that the consumer headers would set.
type H map[string]string

func (s *stack) consumerHeaders(overrides H) http.Header {
	merged := map[string]string{
		"X-Proxy-Strategy":    "up",
		"X-Proxy-Target":      s.mock.URL,
		"Proxy-Authorization": "Bearer {{token}}",
	}
	if s.opts.requireAPIKey {
		merged["Authorization"] = "Bearer " + testAPIKey
	}
	for name, value := range overrides {
		merged[http.CanonicalHeaderKey(name)] = value
	}
	out := http.Header{}
	for name, value := range merged {
		if value != omit || name == "User-Agent" {
			out.Set(name, value)
		}
	}
	return out
}

func (s *stack) newRequest(ctx context.Context, method, path string, header http.Header, body []byte) *http.Request {
	s.t.Helper()
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimSuffix(s.proxy.URL, "/")+path, reader)
	if err != nil {
		s.t.Fatalf("cannot build request: %v", err)
	}
	for name, values := range header {
		switch name {
		case "Host":
			req.Host = values[0]
		case "User-Agent":
			if values[0] == omit {
				req.Header["User-Agent"] = []string{""}
			} else {
				req.Header.Set(name, values[0])
			}
		default:
			req.Header[name] = values
		}
	}
	return req
}

type reply struct {
	status int
	header http.Header
	body   []byte
}

func (s *stack) tryDo(req *http.Request) (reply, error) {
	resp, err := s.client.Do(req)
	if err != nil {
		return reply{}, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return reply{}, err
	}
	return reply{status: resp.StatusCode, header: resp.Header, body: body}, nil
}

func (s *stack) do(req *http.Request) reply {
	s.t.Helper()
	res, err := s.tryDo(req)
	if err != nil {
		s.t.Fatalf("%s %s failed: %v", req.Method, req.URL, err)
	}
	return res
}

func (s *stack) send(method, path string, overrides H, body string) reply {
	s.t.Helper()
	var payload []byte
	if body != "" || method == http.MethodPost {
		payload = []byte(body)
	}
	header := s.consumerHeaders(overrides)
	return s.do(s.newRequest(context.Background(), method, path, header, payload))
}

func (s *stack) sendBytes(method, path string, overrides H, body []byte) reply {
	s.t.Helper()
	return s.do(s.newRequest(context.Background(), method, path, s.consumerHeaders(overrides), body))
}

// bare sends a request without any consumer headers.
func (s *stack) bare(method, path string, extra H) reply {
	s.t.Helper()
	header := http.Header{}
	for name, value := range extra {
		header.Set(name, value)
	}
	return s.do(s.newRequest(context.Background(), method, path, header, nil))
}

func (s *stack) ping(overrides H) reply {
	s.t.Helper()
	return s.send(http.MethodPost, "/ping", overrides, "{}")
}

func (s *stack) stream(ctx context.Context, method, path string, overrides H) *http.Response {
	s.t.Helper()
	resp, err := s.client.Do(s.newRequest(ctx, method, path, s.consumerHeaders(overrides), nil))
	if err != nil {
		s.t.Fatalf("%s %s failed: %v", method, path, err)
	}
	return resp
}

func (r reply) errorDetail(t *testing.T) errorDetail {
	t.Helper()
	if ct := r.header.Get("Content-Type"); ct != "application/json" {
		t.Errorf("error content-type = %q, want application/json", ct)
	}
	var body errorBody
	if err := json.Unmarshal(r.body, &body); err != nil {
		t.Fatalf("response is not an error body: %v (%s)", err, r.body)
	}
	return body.Error
}

func (r reply) wantError(t *testing.T, status int, code string) errorDetail {
	t.Helper()
	detail := r.errorDetail(t)
	if r.status != status || detail.Code != code {
		t.Fatalf("got %d %s (%s), want %d %s", r.status, detail.Code, detail.Message, status, code)
	}
	return detail
}

func (r reply) wantStatus(t *testing.T, status int) {
	t.Helper()
	if r.status != status {
		t.Fatalf("status = %d, want %d (body %s)", r.status, status, r.body)
	}
}

type mcpClient struct {
	t         *testing.T
	s         *stack
	sessionID string
	nextID    int
}

func (c *mcpClient) post(msg rpcMessage) reply {
	c.t.Helper()
	msg.JSONRPC = "2.0"
	payload, err := json.Marshal(msg)
	if err != nil {
		c.t.Fatal(err)
	}
	overrides := H{"Accept": "application/json, text/event-stream", "Content-Type": "application/json"}
	if c.sessionID != "" {
		overrides["Mcp-Session-Id"] = c.sessionID
	}
	return c.s.sendBytes(http.MethodPost, "/", overrides, payload)
}

func (c *mcpClient) call(method string, params any) json.RawMessage {
	c.t.Helper()
	c.nextID++
	id := mustMarshal(c.nextID)
	res := c.post(rpcMessage{ID: id, Method: method, Params: mustMarshal(params)})
	res.wantStatus(c.t, http.StatusOK)
	if c.sessionID == "" {
		c.sessionID = res.header.Get("Mcp-Session-Id")
	}
	msg := parseRPCResponse(c.t, res, id)
	if msg.Error != nil {
		c.t.Fatalf("%s returned a JSON-RPC error: %s", method, msg.Error.Message)
	}
	return msg.Result
}

func (c *mcpClient) notify(method string) {
	c.t.Helper()
	c.post(rpcMessage{Method: method}).wantStatus(c.t, http.StatusAccepted)
}

func parseRPCResponse(t *testing.T, res reply, id json.RawMessage) rpcMessage {
	t.Helper()
	contentType := res.header.Get("Content-Type")
	var candidates [][]byte
	switch {
	case strings.HasPrefix(contentType, "application/json"):
		candidates = append(candidates, res.body)
	case strings.HasPrefix(contentType, "text/event-stream"):
		for _, event := range strings.Split(strings.ReplaceAll(string(res.body), "\r\n", "\n"), "\n\n") {
			var data []string
			for _, line := range strings.Split(event, "\n") {
				if value, ok := strings.CutPrefix(line, "data:"); ok {
					data = append(data, strings.TrimPrefix(value, " "))
				}
			}
			if len(data) > 0 {
				candidates = append(candidates, []byte(strings.Join(data, "\n")))
			}
		}
	default:
		t.Fatalf("unexpected content-type %q", contentType)
	}
	for _, candidate := range candidates {
		var msg rpcMessage
		if err := json.Unmarshal(candidate, &msg); err == nil && string(msg.ID) == string(id) {
			return msg
		}
	}
	t.Fatalf("no JSON-RPC response with id %s in %q", id, res.body)
	return rpcMessage{}
}

func (s *stack) connectMCP() *mcpClient {
	s.t.Helper()
	c := &mcpClient{t: s.t, s: s}
	c.call("initialize", map[string]any{
		"protocolVersion": "2025-03-26",
		"capabilities":    map[string]any{},
		"clientInfo":      map[string]string{"name": "e2e", "version": "0.0.0"},
	})
	if c.sessionID == "" {
		s.t.Fatal("initialize did not return a session id")
	}
	c.notify("notifications/initialized")
	return c
}

func (c *mcpClient) listTools() []string {
	c.t.Helper()
	var result struct {
		Tools []struct {
			Name string `json:"name"`
		} `json:"tools"`
	}
	if err := json.Unmarshal(c.call("tools/list", map[string]any{}), &result); err != nil {
		c.t.Fatal(err)
	}
	names := make([]string, len(result.Tools))
	for i, tool := range result.Tools {
		names[i] = tool.Name
	}
	return names
}

func (c *mcpClient) echo(text string) []toolContent {
	c.t.Helper()
	var result struct {
		Content []toolContent `json:"content"`
	}
	raw := c.call("tools/call", map[string]any{"name": "echo", "arguments": map[string]string{"text": text}})
	if err := json.Unmarshal(raw, &result); err != nil {
		c.t.Fatal(err)
	}
	return result.Content
}
