package bridge

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Oudwins/mcp-auth-proxy/internal/logger"
)

type syncBuffer struct {
	mu  sync.Mutex
	buf strings.Builder
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *syncBuffer) lines() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	text := s.buf.String()
	if text == "" {
		return nil
	}
	return strings.Split(strings.TrimSuffix(text, "\n"), "\n")
}

func (s *syncBuffer) wait(t *testing.T, n int) []string {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if l := s.lines(); len(l) >= n {
			return l
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %d output lines, have %v", n, s.lines())
	return nil
}

type seenRequest struct {
	Method string
	Header http.Header
	Body   string
}

type recorder struct {
	mu   sync.Mutex
	reqs []seenRequest
}

func (r *recorder) add(req *http.Request, body string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.reqs = append(r.reqs, seenRequest{Method: req.Method, Header: req.Header.Clone(), Body: body})
}

func (r *recorder) find(method, bodyContains string) (seenRequest, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, s := range r.reqs {
		if s.Method == method && strings.Contains(s.Body, bodyContains) {
			return s, true
		}
	}
	return seenRequest{}, false
}

func (r *recorder) waitFor(t *testing.T, method, bodyContains string) seenRequest {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if s, ok := r.find(method, bodyContains); ok {
			return s
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s request containing %q", method, bodyContains)
	return seenRequest{}
}

func newServer(t *testing.T, h func(w http.ResponseWriter, r *http.Request, body string)) (*httptest.Server, *recorder) {
	t.Helper()
	rec := &recorder{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		rec.add(r, string(b))
		h(w, r, string(b))
	}))
	t.Cleanup(srv.Close)
	return srv, rec
}

func opts(url string, in io.Reader, out io.Writer) Options {
	return Options{
		Client:   http.DefaultClient,
		URL:      url,
		Strategy: "oauth",
		Target:   "https://mcp.example.com/mcp",
		In:       in,
		Out:      out,
		Log:      logger.Silent,
	}
}

func runString(t *testing.T, o Options) error {
	t.Helper()
	return Run(context.Background(), o)
}

func writeJSON(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, body)
}

type rpcLine struct {
	ID     json.RawMessage `json:"id"`
	Method string          `json:"method"`
	Result json.RawMessage `json:"result"`
	Error  *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

func parseLine(t *testing.T, line string) rpcLine {
	t.Helper()
	var l rpcLine
	if err := json.Unmarshal([]byte(line), &l); err != nil {
		t.Fatalf("output line is not valid JSON: %q: %v", line, err)
	}
	return l
}

func TestInitializeSessionAndProtocolVersion(t *testing.T) {
	srv, rec := newServer(t, func(w http.ResponseWriter, r *http.Request, body string) {
		switch {
		case r.Method == http.MethodDelete:
			w.WriteHeader(http.StatusNoContent)
		case strings.Contains(body, `"initialize"`):
			w.Header().Set("Mcp-Session-Id", "sess-1")
			writeJSON(w, 200, `{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18","capabilities":{}}}`)
		default:
			writeJSON(w, 200, `{"jsonrpc":"2.0","id":2,"result":{"tools":[]}}`)
		}
	})

	pr, pw := io.Pipe()
	out := &syncBuffer{}
	done := make(chan error, 1)
	go func() { done <- Run(context.Background(), opts(srv.URL, pr, out)) }()

	_, _ = io.WriteString(pw, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`+"\n")
	out.wait(t, 1)
	_, _ = io.WriteString(pw, `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`+"\n")
	lines := out.wait(t, 2)
	pw.Close()
	if err := <-done; err != nil {
		t.Fatalf("Run returned %v", err)
	}

	if l := parseLine(t, lines[1]); string(l.ID) != "2" || l.Error != nil {
		t.Fatalf("unexpected second line %q", lines[1])
	}

	first, _ := rec.find(http.MethodPost, `"initialize"`)
	if first.Header.Get("Mcp-Session-Id") != "" || first.Header.Get("MCP-Protocol-Version") != "" {
		t.Fatalf("initialize must not carry session headers: %v", first.Header)
	}
	for _, s := range []seenRequest{
		mustFind(t, rec, http.MethodPost, "tools/list"),
		mustFind(t, rec, http.MethodDelete, ""),
	} {
		if got := s.Header.Get("Mcp-Session-Id"); got != "sess-1" {
			t.Errorf("%s: session id = %q", s.Method, got)
		}
		if got := s.Header.Get("MCP-Protocol-Version"); got != "2025-06-18" {
			t.Errorf("%s: protocol version = %q", s.Method, got)
		}
		if got := s.Header.Get("X-Proxy-Strategy"); got != "oauth" {
			t.Errorf("%s: strategy = %q", s.Method, got)
		}
	}
}

func mustFind(t *testing.T, rec *recorder, method, body string) seenRequest {
	t.Helper()
	s, ok := rec.find(method, body)
	if !ok {
		t.Fatalf("no %s request containing %q", method, body)
	}
	return s
}

func TestSSEResponseMultipleEventsAndSplitData(t *testing.T) {
	srv, _ := newServer(t, func(w http.ResponseWriter, r *http.Request, body string) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(200)
		stream := ": keepalive\r\n" +
			"id: 1\r\n" +
			"event: message\r\n" +
			"data: {\"jsonrpc\":\"2.0\",\r\n" +
			"data: \"method\":\"notifications/progress\",\r\n" +
			"data: \"params\":{\"progress\":1}}\r\n" +
			"\r\n" +
			"event: ping\n" +
			"data: {\"ignored\":true}\n" +
			"\n" +
			"data: {\"jsonrpc\":\"2.0\",\"id\":7,\"result\":{\"ok\":true}}"
		_, _ = io.WriteString(w, stream)
	})

	out := &syncBuffer{}
	in := strings.NewReader(`{"jsonrpc":"2.0","id":7,"method":"tools/call"}` + "\n")
	if err := runString(t, opts(srv.URL, in, out)); err != nil {
		t.Fatalf("Run returned %v", err)
	}

	lines := out.lines()
	if len(lines) != 2 {
		t.Fatalf("expected 2 lines, got %v", lines)
	}
	if lines[0] != `{"jsonrpc":"2.0","method":"notifications/progress","params":{"progress":1}}` {
		t.Errorf("first line = %q", lines[0])
	}
	if lines[1] != `{"jsonrpc":"2.0","id":7,"result":{"ok":true}}` {
		t.Errorf("second line = %q", lines[1])
	}
}

func TestSSEStreamEndsWithoutResponse(t *testing.T) {
	srv, _ := newServer(t, func(w http.ResponseWriter, r *http.Request, body string) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(200)
		_, _ = io.WriteString(w, "data: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/message\"}\n\n")
	})

	out := &syncBuffer{}
	in := strings.NewReader(`{"jsonrpc":"2.0","id":"abc","method":"tools/call"}` + "\n")
	if err := runString(t, opts(srv.URL, in, out)); err != nil {
		t.Fatalf("Run returned %v", err)
	}
	lines := out.lines()
	if len(lines) != 2 {
		t.Fatalf("expected 2 lines, got %v", lines)
	}
	l := parseLine(t, lines[1])
	if string(l.ID) != `"abc"` || l.Error == nil || l.Error.Code != -32000 || l.Error.Message != "stream ended before a response was received" {
		t.Fatalf("unexpected synthesized error %q", lines[1])
	}
}

func TestNotificationAcceptedWritesNothing(t *testing.T) {
	for _, status := range []int{http.StatusAccepted, http.StatusNoContent} {
		srv, rec := newServer(t, func(w http.ResponseWriter, r *http.Request, body string) {
			w.WriteHeader(status)
		})
		out := &syncBuffer{}
		in := strings.NewReader(`{"jsonrpc":"2.0","method":"notifications/cancelled","params":{}}` + "\n\n  \n")
		if err := runString(t, opts(srv.URL, in, out)); err != nil {
			t.Fatalf("Run returned %v", err)
		}
		if l := out.lines(); len(l) != 0 {
			t.Fatalf("status %d: expected no output, got %v", status, l)
		}
		mustFind(t, rec, http.MethodPost, "notifications/cancelled")
	}
}

func TestProxyShapedErrorBody(t *testing.T) {
	srv, _ := newServer(t, func(w http.ResponseWriter, r *http.Request, body string) {
		writeJSON(w, 401, `{"error":{"code":"auth_failed","message":"token expired"}}`)
	})
	out := &syncBuffer{}
	in := strings.NewReader(`{"jsonrpc":"2.0","id":"req-5","method":"tools/list"}` + "\n")
	if err := runString(t, opts(srv.URL, in, out)); err != nil {
		t.Fatalf("Run returned %v", err)
	}
	lines := out.lines()
	if len(lines) != 1 {
		t.Fatalf("expected 1 line, got %v", lines)
	}
	l := parseLine(t, lines[0])
	if string(l.ID) != `"req-5"` || l.Error == nil || l.Error.Code != -32000 {
		t.Fatalf("unexpected error line %q", lines[0])
	}
	if !strings.Contains(l.Error.Message, "401") || !strings.Contains(l.Error.Message, "auth_failed: token expired") {
		t.Fatalf("message = %q", l.Error.Message)
	}
}

func TestPlainErrorBodyTruncated(t *testing.T) {
	srv, _ := newServer(t, func(w http.ResponseWriter, r *http.Request, body string) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(500)
		_, _ = io.WriteString(w, strings.Repeat("x", 2000))
	})
	out := &syncBuffer{}
	in := strings.NewReader(`{"jsonrpc":"2.0","id":3,"method":"tools/list"}` + "\n")
	if err := runString(t, opts(srv.URL, in, out)); err != nil {
		t.Fatalf("Run returned %v", err)
	}
	l := parseLine(t, out.lines()[0])
	if l.Error == nil || !strings.HasPrefix(l.Error.Message, "HTTP 500: xxx") {
		t.Fatalf("unexpected error %+v", l.Error)
	}
	if n := strings.Count(l.Error.Message, "x"); n != 512 {
		t.Fatalf("body truncated to %d bytes, want 512", n)
	}
}

func TestErrorForNotificationOnlyLogged(t *testing.T) {
	srv, _ := newServer(t, func(w http.ResponseWriter, r *http.Request, body string) {
		writeJSON(w, 500, `{"error":{"code":"boom","message":"bad"}}`)
	})
	out := &syncBuffer{}
	in := strings.NewReader(`{"jsonrpc":"2.0","method":"notifications/initialized"}` + "\n")
	if err := runString(t, opts(srv.URL, in, out)); err != nil {
		t.Fatalf("Run returned %v", err)
	}
	if l := out.lines(); len(l) != 0 {
		t.Fatalf("expected no output, got %v", l)
	}
}

func TestTransportError(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	url := srv.URL
	srv.Close()

	out := &syncBuffer{}
	in := strings.NewReader(`{"jsonrpc":"2.0","id":11,"method":"tools/list"}` + "\n")
	if err := runString(t, opts(url, in, out)); err != nil {
		t.Fatalf("Run returned %v", err)
	}
	lines := out.lines()
	if len(lines) != 1 {
		t.Fatalf("expected 1 line, got %v", lines)
	}
	l := parseLine(t, lines[0])
	if string(l.ID) != "11" || l.Error == nil || l.Error.Code != -32000 || l.Error.Message == "" {
		t.Fatalf("unexpected line %q", lines[0])
	}
}

func TestConcurrentRequestsOutOfOrder(t *testing.T) {
	release := make(chan struct{})
	big := strings.Repeat("a", 200000)
	srv, _ := newServer(t, func(w http.ResponseWriter, r *http.Request, body string) {
		if strings.Contains(body, `"id":1,`) {
			select {
			case <-release:
			case <-time.After(5 * time.Second):
			}
			writeJSON(w, 200, `{"jsonrpc":"2.0","id":1,"result":{"data":"`+big+`"}}`)
			return
		}
		writeJSON(w, 200, `{"jsonrpc":"2.0","id":2,"result":{"data":"`+big+`"}}`)
	})

	pr, pw := io.Pipe()
	out := &syncBuffer{}
	done := make(chan error, 1)
	go func() { done <- Run(context.Background(), opts(srv.URL, pr, out)) }()

	_, _ = io.WriteString(pw, `{"jsonrpc":"2.0","id":1,"method":"slow"}`+"\n")
	time.Sleep(50 * time.Millisecond)
	_, _ = io.WriteString(pw, `{"jsonrpc":"2.0","id":2,"method":"fast"}`+"\n")
	out.wait(t, 1)
	close(release)
	lines := out.wait(t, 2)
	pw.Close()
	if err := <-done; err != nil {
		t.Fatalf("Run returned %v", err)
	}

	first, second := parseLine(t, lines[0]), parseLine(t, lines[1])
	if string(first.ID) != "2" || string(second.ID) != "1" {
		t.Fatalf("expected ids 2 then 1, got %s then %s", first.ID, second.ID)
	}
	for _, l := range lines {
		if len(l) < len(big) || strings.Contains(l, "\n") {
			t.Fatalf("line damaged, length %d", len(l))
		}
	}
}

func TestExtraAndProxyHeaders(t *testing.T) {
	srv, rec := newServer(t, func(w http.ResponseWriter, r *http.Request, body string) {
		writeJSON(w, 200, `{"jsonrpc":"2.0","id":1,"result":{}}`)
	})
	o := opts(srv.URL, strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`+"\n"), &syncBuffer{})
	o.Headers = http.Header{
		"X-Api-Key": {"{{secret}}"},
		"X-Multi":   {"a", "b"},
	}
	if err := runString(t, o); err != nil {
		t.Fatalf("Run returned %v", err)
	}
	s := mustFind(t, rec, http.MethodPost, "ping")
	checks := map[string]string{
		"Content-Type":     "application/json",
		"Accept":           "application/json, text/event-stream",
		"X-Proxy-Strategy": "oauth",
		"X-Proxy-Target":   "https://mcp.example.com/mcp",
		"X-Api-Key":        "{{secret}}",
	}
	for k, want := range checks {
		if got := s.Header.Get(k); got != want {
			t.Errorf("header %s = %q, want %q", k, got, want)
		}
	}
	if got := s.Header.Values("X-Multi"); len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Errorf("X-Multi = %v", got)
	}
}

func TestEOFWaitsForPendingWork(t *testing.T) {
	srv, _ := newServer(t, func(w http.ResponseWriter, r *http.Request, body string) {
		time.Sleep(150 * time.Millisecond)
		writeJSON(w, 200, `{"jsonrpc":"2.0","id":1,"result":{}}`)
	})
	out := &syncBuffer{}
	in := strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}` + "\n")
	if err := runString(t, opts(srv.URL, in, out)); err != nil {
		t.Fatalf("Run returned %v", err)
	}
	if l := out.lines(); len(l) != 1 {
		t.Fatalf("expected 1 line after EOF, got %v", l)
	}
}

func TestLastLineWithoutNewline(t *testing.T) {
	srv, _ := newServer(t, func(w http.ResponseWriter, r *http.Request, body string) {
		writeJSON(w, 200, `{"jsonrpc":"2.0","id":1,"result":{}}`)
	})
	out := &syncBuffer{}
	in := strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`)
	if err := runString(t, opts(srv.URL, in, out)); err != nil {
		t.Fatalf("Run returned %v", err)
	}
	if l := out.lines(); len(l) != 1 {
		t.Fatalf("expected 1 line, got %v", l)
	}
}

func TestInvalidJSONPayloadDropped(t *testing.T) {
	srv, _ := newServer(t, func(w http.ResponseWriter, r *http.Request, body string) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(200)
		_, _ = io.WriteString(w, "data: not json\n\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\n\n")
	})
	out := &syncBuffer{}
	in := strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}` + "\n")
	if err := runString(t, opts(srv.URL, in, out)); err != nil {
		t.Fatalf("Run returned %v", err)
	}
	if l := out.lines(); len(l) != 1 || !strings.Contains(l[0], `"result"`) {
		t.Fatalf("unexpected output %v", l)
	}
}

func TestGetStreamForwardsServerMessages(t *testing.T) {
	srv, rec := newServer(t, func(w http.ResponseWriter, r *http.Request, body string) {
		switch {
		case r.Method == http.MethodGet:
			w.Header().Set("Content-Type", "text/event-stream")
			w.WriteHeader(200)
			_, _ = io.WriteString(w, "id: 42\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/tools/list_changed\"}\n\n")
			w.(http.Flusher).Flush()
			<-r.Context().Done()
		case r.Method == http.MethodDelete:
			w.WriteHeader(http.StatusNoContent)
		case strings.Contains(body, `"initialize"`):
			w.Header().Set("Mcp-Session-Id", "sess-9")
			writeJSON(w, 200, `{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-03-26"}}`)
		default:
			w.WriteHeader(http.StatusAccepted)
		}
	})

	pr, pw := io.Pipe()
	out := &syncBuffer{}
	done := make(chan error, 1)
	go func() { done <- Run(context.Background(), opts(srv.URL, pr, out)) }()

	_, _ = io.WriteString(pw, `{"jsonrpc":"2.0","id":1,"method":"initialize"}`+"\n")
	out.wait(t, 1)
	_, _ = io.WriteString(pw, `{"jsonrpc":"2.0","method":"notifications/initialized"}`+"\n")
	lines := out.wait(t, 2)
	pw.Close()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run returned %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after stdin EOF with an open GET stream")
	}

	if lines[1] != `{"jsonrpc":"2.0","method":"notifications/tools/list_changed"}` {
		t.Errorf("forwarded line = %q", lines[1])
	}
	get := mustFind(t, rec, http.MethodGet, "")
	if get.Header.Get("Accept") != "text/event-stream" {
		t.Errorf("GET Accept = %q", get.Header.Get("Accept"))
	}
	if get.Header.Get("Mcp-Session-Id") != "sess-9" || get.Header.Get("MCP-Protocol-Version") != "2025-03-26" {
		t.Errorf("GET session headers = %v", get.Header)
	}
	if get.Header.Get("X-Proxy-Target") == "" {
		t.Errorf("GET missing X-Proxy-Target")
	}
	mustFind(t, rec, http.MethodDelete, "")
}

func TestGetStream405StopsQuietly(t *testing.T) {
	srv, rec := newServer(t, func(w http.ResponseWriter, r *http.Request, body string) {
		if r.Method == http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.WriteHeader(http.StatusAccepted)
	})

	pr, pw := io.Pipe()
	out := &syncBuffer{}
	done := make(chan error, 1)
	go func() { done <- Run(context.Background(), opts(srv.URL, pr, out)) }()

	_, _ = io.WriteString(pw, `{"jsonrpc":"2.0","method":"notifications/initialized"}`+"\n")
	rec.waitFor(t, http.MethodGet, "")
	time.Sleep(50 * time.Millisecond)
	pw.Close()
	if err := <-done; err != nil {
		t.Fatalf("Run returned %v", err)
	}
	if l := out.lines(); len(l) != 0 {
		t.Fatalf("expected no output, got %v", l)
	}
	rec.mu.Lock()
	defer rec.mu.Unlock()
	gets := 0
	for _, s := range rec.reqs {
		if s.Method == http.MethodGet {
			gets++
		}
	}
	if gets != 1 {
		t.Fatalf("expected exactly 1 GET, got %d", gets)
	}
}

func TestContextCancelReturnsNil(t *testing.T) {
	started := make(chan struct{})
	srv, _ := newServer(t, func(w http.ResponseWriter, r *http.Request, body string) {
		close(started)
		<-r.Context().Done()
	})
	pr, pw := io.Pipe()
	defer pw.Close()
	out := &syncBuffer{}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Run(ctx, opts(srv.URL, pr, out)) }()

	_, _ = io.WriteString(pw, `{"jsonrpc":"2.0","id":1,"method":"slow"}`+"\n")
	<-started
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run returned %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after cancel")
	}
	if l := out.lines(); len(l) != 0 {
		t.Fatalf("expected no output after cancel, got %v", l)
	}
}

func TestReadSSE(t *testing.T) {
	input := "\uFEFF: comment\r\nevent: custom\r\nid: 5\r\ndata: a\r\ndata:b\r\n\r\nid: 6\n\ndata: tail"
	var got []sseEvent
	if err := readSSE(strings.NewReader(input), func(ev sseEvent) { got = append(got, ev) }); err != nil {
		t.Fatal(err)
	}
	want := []sseEvent{
		{Event: "custom", ID: "5", Data: "a\nb"},
		{ID: "6"},
		{Data: "tail"},
	}
	if len(got) != len(want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("event %d = %+v, want %+v", i, got[i], want[i])
		}
	}
}

func TestReadSSELargeEvent(t *testing.T) {
	payload := strings.Repeat("z", 1<<20)
	var got string
	if err := readSSE(strings.NewReader("data: "+payload+"\n\n"), func(ev sseEvent) { got = ev.Data }); err != nil {
		t.Fatal(err)
	}
	if got != payload {
		t.Fatalf("large event damaged, len %d", len(got))
	}
}
