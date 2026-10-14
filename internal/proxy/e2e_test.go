package proxy

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func tokenOf(req seenRequest) string {
	return req.Header.Get("Proxy-Authorization")
}

func wantTokenSerial(t *testing.T, req seenRequest, serial int) {
	t.Helper()
	prefix := fmt.Sprintf("Bearer tok.%d.", serial)
	if got := tokenOf(req); !strings.HasPrefix(got, prefix) {
		t.Errorf("Proxy-Authorization = %q, want prefix %q", got, prefix)
	}
}

func filterMethod(all []seenRequest, method string) []seenRequest {
	var out []seenRequest
	for _, req := range all {
		if req.Method == method {
			out = append(out, req)
		}
	}
	return out
}

func wantRequests(t *testing.T, s *stack, n int) {
	t.Helper()
	if got := len(s.mock.requests()); got != n {
		t.Fatalf("upstream saw %d requests, want %d", got, n)
	}
}

func wantRuns(t *testing.T, s *stack, n int) {
	t.Helper()
	if got := s.generatorRuns(); got != n {
		t.Fatalf("generator ran %d times, want %d", got, n)
	}
}

func TestMCPClientThroughProxy(t *testing.T) {
	for _, mode := range []struct {
		name string
		sse  bool
	}{{"json responses", false}, {"sse responses", true}} {
		t.Run(mode.name, func(t *testing.T) {
			t.Parallel()
			s := startStack(t, stackOptions{requireAPIKey: true, mockSSE: mode.sse})
			wantRuns(t, s, 0)

			client := s.connectMCP()
			if got := client.listTools(); !reflect.DeepEqual(got, []string{"echo"}) {
				t.Fatalf("tools = %v", got)
			}
			if got := client.echo("hi"); !reflect.DeepEqual(got, []toolContent{{Type: "text", Text: "echo:hi"}}) {
				t.Fatalf("echo = %v", got)
			}
			if got := client.echo("again"); !reflect.DeepEqual(got, []toolContent{{Type: "text", Text: "echo:again"}}) {
				t.Fatalf("echo = %v", got)
			}

			wantRuns(t, s, 1)
			seen := s.mock.requests()
			if len(seen) != 5 {
				t.Fatalf("upstream saw %d requests, want 5", len(seen))
			}
			for _, req := range seen {
				wantTokenSerial(t, req, 1)
				if got := req.Header.Get("Authorization"); got != "Bearer "+testAPIKey {
					t.Errorf("Authorization = %q", got)
				}
				for name := range req.Header {
					if strings.HasPrefix(strings.ToLower(name), "x-proxy-") {
						t.Errorf("control header %s reached the upstream", name)
					}
				}
			}
		})
	}
}

func TestProactiveRefreshBeforeExpiry(t *testing.T) {
	t.Parallel()
	s := startStack(t, stackOptions{genFormat: "expiring", expiresIn: 4, skew: 3.2})
	client := s.connectMCP()
	client.echo("one")
	wantRuns(t, s, 1)

	time.Sleep(900 * time.Millisecond)

	if got := client.echo("two"); !reflect.DeepEqual(got, []toolContent{{Type: "text", Text: "echo:two"}}) {
		t.Fatalf("echo = %v", got)
	}
	wantRuns(t, s, 2)
	all := s.mock.requests()
	for _, req := range all {
		if req.Status == http.StatusUnauthorized {
			t.Errorf("upstream rejected %s %s", req.Method, req.URL)
		}
	}
	wantTokenSerial(t, all[len(all)-1], 2)
}

func TestStaleCredentialsAreReusedWhenRefreshFails(t *testing.T) {
	t.Parallel()
	s := startStack(t, stackOptions{genFormat: "expiring", expiresIn: 4, skew: 3.2})
	s.ping(nil).wantStatus(t, http.StatusOK)
	s.makeGeneratorFail()

	time.Sleep(900 * time.Millisecond)
	res := s.ping(nil)

	res.wantStatus(t, http.StatusOK)
	wantRuns(t, s, 1)
	wantTokenSerial(t, s.mock.last(t), 1)
	if !strings.Contains(s.logs.String(), "refresh failed, reusing credentials until they expire") {
		t.Errorf("no stale fallback warning in logs:\n%s", s.logs.String())
	}
}

func TestReauthenticatesAndReplaysWhenUpstreamRevokesTheToken(t *testing.T) {
	t.Parallel()
	s := startStack(t, stackOptions{})
	client := s.connectMCP()
	client.echo("one")

	s.mock.revokeThrough(s.generatorRuns())
	if got := client.echo("two"); !reflect.DeepEqual(got, []toolContent{{Type: "text", Text: "echo:two"}}) {
		t.Fatalf("echo = %v", got)
	}

	wantRuns(t, s, 2)
	if got := s.forceFlags(); !reflect.DeepEqual(got, []string{"0", "1"}) {
		t.Errorf("force flags = %v", got)
	}
	posts := filterMethod(s.mock.requests(), http.MethodPost)
	rejected, replayed := posts[len(posts)-2], posts[len(posts)-1]
	if rejected.Status != http.StatusUnauthorized || replayed.Status != http.StatusOK {
		t.Errorf("statuses = %d then %d, want 401 then 200", rejected.Status, replayed.Status)
	}
	if !bytes.Equal(rejected.Body, replayed.Body) || len(replayed.Body) == 0 {
		t.Errorf("replayed body differs: %q vs %q", rejected.Body, replayed.Body)
	}
	if rejected.ContentLength != replayed.ContentLength {
		t.Errorf("content-length differs: %d vs %d", rejected.ContentLength, replayed.ContentLength)
	}
}

func TestRejectionHandling(t *testing.T) {
	t.Parallel()

	t.Run("retries a rejected request once and then passes the 401 through", func(t *testing.T) {
		t.Parallel()
		s := startStack(t, stackOptions{})
		s.mock.setRejectAll(true)

		s.ping(nil).wantStatus(t, http.StatusUnauthorized)

		wantRuns(t, s, 2)
		wantRequests(t, s, 2)
	})

	t.Run("does not loop when the new credentials are identical", func(t *testing.T) {
		t.Parallel()
		s := startStack(t, stackOptions{genFormat: "static"})
		s.mock.setRejectAll(true)

		s.ping(nil).wantStatus(t, http.StatusUnauthorized)

		wantRuns(t, s, 2)
		wantRequests(t, s, 1)
	})

	t.Run("does not re-run the generator within the cooldown window", func(t *testing.T) {
		t.Parallel()
		s := startStack(t, stackOptions{cooldown: 60})
		s.mock.setRejectAll(true)

		s.ping(nil).wantStatus(t, http.StatusUnauthorized)
		s.ping(nil).wantStatus(t, http.StatusUnauthorized)

		wantRuns(t, s, 1)
	})

	t.Run("only retries on configured status codes", func(t *testing.T) {
		t.Parallel()
		s := startStack(t, stackOptions{retryOnStatus: []int{403}})
		s.mock.setRejectAll(true)

		s.ping(nil).wantStatus(t, http.StatusUnauthorized)

		wantRuns(t, s, 1)
	})

	t.Run("retries on a configured non-default status", func(t *testing.T) {
		t.Parallel()
		s := startStack(t, stackOptions{retryOnStatus: []int{403}, requireAPIKey: true})

		s.ping(H{"Authorization": "Bearer wrong"}).wantStatus(t, http.StatusForbidden)

		wantRuns(t, s, 2)
		wantRequests(t, s, 2)
	})

	t.Run("re-renders every placeholder with the fresh credentials on the retry", func(t *testing.T) {
		t.Parallel()
		s := startStack(t, stackOptions{})
		s.ping(nil)
		s.mock.revokeThrough(1)

		res := s.send(http.MethodPost, "/ping", H{
			"Proxy-Authorization": omit,
			"X-Proxy-Target":      s.mock.URL + "?access_token={{token}}",
			"X-Echo":              "{{token}}",
		}, "payload-123")

		res.wantStatus(t, http.StatusOK)
		all := s.mock.requests()
		rejected, replayed := all[len(all)-2], all[len(all)-1]
		if !strings.Contains(rejected.URL, "access_token=tok.1.") || !strings.Contains(replayed.URL, "access_token=tok.2.") {
			t.Errorf("urls = %q then %q", rejected.URL, replayed.URL)
		}
		if !strings.HasPrefix(rejected.Header.Get("X-Echo"), "tok.1.") || !strings.HasPrefix(replayed.Header.Get("X-Echo"), "tok.2.") {
			t.Errorf("x-echo = %q then %q", rejected.Header.Get("X-Echo"), replayed.Header.Get("X-Echo"))
		}
		if string(rejected.Body) != "payload-123" || string(replayed.Body) != "payload-123" {
			t.Errorf("bodies = %q then %q", rejected.Body, replayed.Body)
		}
	})
}

func TestCredentialGeneration(t *testing.T) {
	t.Parallel()

	t.Run("runs the generator once for many concurrent requests", func(t *testing.T) {
		t.Parallel()
		s := startStack(t, stackOptions{genDelay: 0.4})

		const count = 6
		requests := make([]*http.Request, count)
		for i := range requests {
			requests[i] = s.newRequest(context.Background(), http.MethodPost, "/ping", s.consumerHeaders(nil), []byte("{}"))
		}
		statuses := make([]int, count)
		var wg sync.WaitGroup
		for i, req := range requests {
			wg.Add(1)
			go func() {
				defer wg.Done()
				res, err := s.tryDo(req)
				if err != nil {
					statuses[i] = -1
					return
				}
				statuses[i] = res.status
			}()
		}
		wg.Wait()

		for i, status := range statuses {
			if status != http.StatusOK {
				t.Errorf("request %d status = %d", i, status)
			}
		}
		wantRuns(t, s, 1)
	})

	t.Run("returns a descriptive 502 with redacted stderr when the generator fails, then recovers", func(t *testing.T) {
		t.Parallel()
		s := startStack(t, stackOptions{})
		s.makeGeneratorFail()

		detail := s.ping(nil).wantError(t, http.StatusBadGateway, "auth_command_failed")

		if !strings.Contains(detail.Message, "ADC credentials expired") || !strings.HasPrefix(detail.Message, "[up] ") {
			t.Errorf("message = %q", detail.Message)
		}
		if strings.Contains(detail.Message, "leaked.secret-value") || !strings.Contains(detail.Message, "Bearer <redacted>") {
			t.Errorf("stderr was not redacted: %q", detail.Message)
		}
		if strings.Contains(s.logs.String(), "leaked.secret-value") {
			t.Errorf("secret reached the logs:\n%s", s.logs.String())
		}
		wantRequests(t, s, 0)

		s.makeGeneratorSucceed()
		s.ping(nil).wantStatus(t, http.StatusOK)
	})

	t.Run("supports bare-token output and argv commands and tells the command its strategy", func(t *testing.T) {
		t.Parallel()
		s := startStack(t, stackOptions{genFormat: "token", commandArray: true})

		s.ping(nil).wantStatus(t, http.StatusOK)

		wantTokenSerial(t, s.mock.last(t), 1)
		if got := s.strategyName(); got != "up" {
			t.Errorf("strategy name = %q", got)
		}
	})

	t.Run("exposes every value of a json strategy as its own placeholder", func(t *testing.T) {
		t.Parallel()
		s := startStack(t, stackOptions{genFormat: "multi"})

		res := s.send(http.MethodPost, "/", H{
			"X-Tenant":       "{{tenant}}",
			"X-Proxy-Target": s.mock.URL + "/ping/{{tenant}}?tenant={{tenant}}",
		}, "{}")

		res.wantStatus(t, http.StatusOK)
		seen := s.mock.last(t)
		if got := seen.Header.Get("X-Tenant"); got != "acme corp" {
			t.Errorf("x-tenant = %q", got)
		}
		if seen.URL != "/mcp/ping/acme%20corp?tenant=acme%20corp" {
			t.Errorf("url = %q", seen.URL)
		}
		wantTokenSerial(t, seen, 1)
	})
}

func TestPlaceholderInjection(t *testing.T) {
	t.Parallel()

	t.Run("fills placeholders in headers, target path and target query", func(t *testing.T) {
		t.Parallel()
		s := startStack(t, stackOptions{})

		res := s.send(http.MethodPost, "/", H{
			"X-Proxy-Target": s.mock.URL + "/ping/{{token}}?access_token={{token}}&fixed=1",
			"X-Copy":         "token={{ token }}",
		}, "{}")

		res.wantStatus(t, http.StatusOK)
		seen := s.mock.last(t)
		if !regexp.MustCompile(`^/mcp/ping/tok\.1\.\d+\?access_token=tok\.1\.\d+&fixed=1$`).MatchString(seen.URL) {
			t.Errorf("url = %q", seen.URL)
		}
		if !strings.HasPrefix(seen.Header.Get("X-Copy"), "token=tok.1.") {
			t.Errorf("x-copy = %q", seen.Header.Get("X-Copy"))
		}
		wantTokenSerial(t, seen, 1)
	})

	t.Run("accepts the credential through the query alone", func(t *testing.T) {
		t.Parallel()
		s := startStack(t, stackOptions{})

		res := s.ping(H{"Proxy-Authorization": omit, "X-Proxy-Target": s.mock.URL + "?access_token={{token}}"})

		res.wantStatus(t, http.StatusOK)
		if got := tokenOf(s.mock.last(t)); got != "" {
			t.Errorf("Proxy-Authorization = %q, want none", got)
		}
	})

	t.Run("accepts the credential through the path alone, URL-encoded", func(t *testing.T) {
		t.Parallel()
		s := startStack(t, stackOptions{genFormat: "multi"})

		res := s.send(http.MethodPost, "/", H{
			"X-Proxy-Target":      s.mock.URL + "/ping/{{tenant}}?access_token={{token}}",
			"Proxy-Authorization": omit,
		}, "{}")

		res.wantStatus(t, http.StatusOK)
		if got := s.mock.last(t).URL; !strings.HasPrefix(got, "/mcp/ping/acme%20corp?access_token=tok.1.") {
			t.Errorf("url = %q", got)
		}
	})

	t.Run("keeps slashes and question marks inside a value encoded", func(t *testing.T) {
		t.Parallel()
		s := startStack(t, stackOptions{genFormat: "multi", tenant: "a/b?c=d"})

		res := s.send(http.MethodPost, "/", H{
			"X-Proxy-Target": s.mock.URL + "/ping/{{tenant}}?tenant={{tenant}}",
			"X-Tenant":       "{{tenant}}",
		}, "{}")

		res.wantStatus(t, http.StatusOK)
		seen := s.mock.last(t)
		if want := "/mcp/ping/a%2Fb%3Fc%3Dd?tenant=a%2Fb%3Fc%3Dd"; seen.URL != want {
			t.Errorf("url = %q, want %q", seen.URL, want)
		}
		if got := seen.Header.Get("X-Tenant"); got != "a/b?c=d" {
			t.Errorf("header values must stay raw, got %q", got)
		}
	})

	t.Run("renders the escape sequence as a literal and does not count it as a placeholder", func(t *testing.T) {
		t.Parallel()
		s := startStack(t, stackOptions{})

		s.ping(H{"X-Literal": `\{{token}}`}).wantStatus(t, http.StatusOK)
		if got := s.mock.last(t).Header.Get("X-Literal"); got != "{{token}}" {
			t.Errorf("x-literal = %q", got)
		}

		s.ping(H{"Proxy-Authorization": omit, "X-Literal": `\{{token}}`}).wantError(t, http.StatusBadRequest, "no_placeholder")
	})

	t.Run("rejects an unknown placeholder and lists the names the strategy provides", func(t *testing.T) {
		t.Parallel()
		s := startStack(t, stackOptions{})

		detail := s.ping(H{"X-Bad": "{{nope}}"}).wantError(t, http.StatusBadRequest, "unknown_placeholder")

		if !strings.Contains(detail.Message, "{{nope}}") || !strings.Contains(detail.Message, "{{token}}") {
			t.Errorf("message = %q", detail.Message)
		}
		wantRequests(t, s, 0)
	})

	t.Run("rejects an unknown placeholder in the target path", func(t *testing.T) {
		t.Parallel()
		s := startStack(t, stackOptions{})

		s.ping(H{"X-Proxy-Target": s.mock.URL + "/{{nope}}"}).wantError(t, http.StatusBadRequest, "unknown_placeholder")

		wantRequests(t, s, 0)
	})

	t.Run("rejects a request without any placeholder before running the generator", func(t *testing.T) {
		t.Parallel()
		s := startStack(t, stackOptions{})

		s.ping(H{"Proxy-Authorization": omit}).wantError(t, http.StatusBadRequest, "no_placeholder")

		wantRuns(t, s, 0)
		wantRequests(t, s, 0)
	})

	t.Run("ignores placeholders in control headers when deciding", func(t *testing.T) {
		t.Parallel()
		s := startStack(t, stackOptions{})

		s.ping(H{"Proxy-Authorization": omit, "X-Proxy-Note": "{{token}}"}).wantError(t, http.StatusBadRequest, "no_placeholder")

		wantRuns(t, s, 0)
	})

	t.Run("renders each value of a repeated header separately", func(t *testing.T) {
		t.Parallel()
		s := startStack(t, stackOptions{genFormat: "multi"})
		req := s.newRequest(context.Background(), http.MethodPost, "/ping", s.consumerHeaders(nil), []byte("{}"))
		req.Header.Add("X-Multi", "a-{{tenant}}")
		req.Header.Add("X-Multi", "b-{{tenant}}")

		s.do(req).wantStatus(t, http.StatusOK)

		if got := s.mock.last(t).Header.Values("X-Multi"); !reflect.DeepEqual(got, []string{"a-acme corp", "b-acme corp"}) {
			t.Errorf("x-multi = %q", got)
		}
	})
}

func TestStrategyAndTargetValidation(t *testing.T) {
	t.Parallel()

	t.Run("requires a known strategy", func(t *testing.T) {
		t.Parallel()
		s := startStack(t, stackOptions{extraStrategies: []string{"zeta", "alpha"}})

		missing := s.ping(H{"X-Proxy-Strategy": omit}).wantError(t, http.StatusBadRequest, "missing_strategy")
		unknown := s.ping(H{"X-Proxy-Strategy": "nope"}).wantError(t, http.StatusBadRequest, "unknown_strategy")
		s.ping(H{"X-Proxy-Strategy": "constructor"}).wantError(t, http.StatusBadRequest, "unknown_strategy")
		s.ping(H{"X-Proxy-Strategy": "UP"}).wantError(t, http.StatusBadRequest, "unknown_strategy")

		if !strings.Contains(missing.Message, "available: alpha, up, zeta") {
			t.Errorf("missing message = %q", missing.Message)
		}
		if want := `no strategy named "nope"; available: alpha, up, zeta`; unknown.Message != want {
			t.Errorf("unknown message = %q, want %q", unknown.Message, want)
		}
		wantRuns(t, s, 0)
	})

	t.Run("requires a well-formed target", func(t *testing.T) {
		t.Parallel()
		s := startStack(t, stackOptions{})

		s.ping(H{"X-Proxy-Target": omit}).wantError(t, http.StatusBadRequest, "missing_target")

		origin := s.mock.origin()
		invalid := []string{
			"not a url",
			"/relative/path",
			"ftp://127.0.0.1/x",
			origin + "/x#fragment",
			"http://user:pass@127.0.0.1/x",
			"http://a@b/x",
			`http://127.0.0.1\@evil.example/x`,
			"http://{{token}}/x",
			"http://127.0.0.1:{{token}}/x",
			"http://{{token}}.127.0.0.1/x",
			"http:///x",
			"http://127.0.0.1:123456/x",
			"http://-bad/x",
			"http://bad-/x",
		}
		for _, value := range invalid {
			s.ping(H{"X-Proxy-Target": value}).wantError(t, http.StatusBadRequest, "invalid_target")
		}
		wantRuns(t, s, 0)
		wantRequests(t, s, 0)
	})

	t.Run("accepts an upper-case scheme and surrounding whitespace", func(t *testing.T) {
		t.Parallel()
		s := startStack(t, stackOptions{})
		target := "  HTTP://" + strings.TrimPrefix(s.mock.URL, "http://") + "  "

		s.ping(H{"X-Proxy-Target": target}).wantStatus(t, http.StatusOK)
	})

	t.Run("refuses hosts outside the allowed list without running the generator", func(t *testing.T) {
		t.Parallel()
		s := startStack(t, stackOptions{})
		port := mustPort(t, s.mock.URL)

		blocked := []string{
			"http://127.0.0.2:" + port + "/mcp",
			"https://127.0.0.1:" + port + "/mcp",
			"http://127.0.0.1:" + strconv.Itoa(mustAtoi(t, port)+1) + "/mcp",
			"https://example.com/mcp",
		}
		for _, value := range blocked {
			s.ping(H{"X-Proxy-Target": value}).wantError(t, http.StatusForbidden, "target_not_allowed")
		}
		wantRuns(t, s, 0)
	})

	t.Run("matches wildcards on subdomains with the same scheme and port only", func(t *testing.T) {
		t.Parallel()
		s := startStack(t, stackOptions{globalAllowedHosts: []string{"*.example.com", "http://*.plain.example:8080"}})

		blocked := []string{
			"https://example.com/mcp",
			"http://a.example.com/mcp",
			"https://a.example.com:8443/mcp",
			"https://evil-example.com/mcp",
			"https://a.example.com.evil.net/mcp",
			"http://a.plain.example/mcp",
			"https://a.plain.example:8080/mcp",
		}
		for _, value := range blocked {
			s.ping(H{"X-Proxy-Target": value}).wantError(t, http.StatusForbidden, "target_not_allowed")
		}
		wantRuns(t, s, 0)
	})

	t.Run("uses the global allowedHosts when the strategy has none", func(t *testing.T) {
		t.Parallel()
		s := startStack(t, stackOptions{globalAllowedHosts: []string{"only.example.com"}})

		s.ping(nil).wantError(t, http.StatusForbidden, "target_not_allowed")
	})

	t.Run("lets a strategy allowedHosts list replace the global one, in both directions", func(t *testing.T) {
		t.Parallel()
		denied := startStack(t, stackOptions{strategyAllowedHosts: []string{"only.example.com"}})
		detail := denied.ping(nil).wantError(t, http.StatusForbidden, "target_not_allowed")
		if !strings.Contains(detail.Message, "only.example.com") || !strings.Contains(detail.Message, `strategy "up"`) {
			t.Errorf("message = %q", detail.Message)
		}

		allowed := startStack(t, stackOptions{
			globalAllowedHosts:   []string{"only.example.com"},
			strategyAllowedHosts: []string{mockHostToken},
		})
		allowed.ping(nil).wantStatus(t, http.StatusOK)
	})

	t.Run("does not follow redirects", func(t *testing.T) {
		t.Parallel()
		s := startStack(t, stackOptions{})

		res := s.send(http.MethodPost, "/redirect", nil, "{}")

		res.wantStatus(t, http.StatusFound)
		if got := res.header.Get("Location"); got != "http://127.0.0.1:9/elsewhere" {
			t.Errorf("location = %q", got)
		}
		wantRequests(t, s, 1)
	})
}

func mustAtoi(t *testing.T, value string) int {
	t.Helper()
	n, err := strconv.Atoi(value)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func mustPort(t *testing.T, rawURL string) string {
	t.Helper()
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatal(err)
	}
	return u.Port()
}

func TestForwarding(t *testing.T) {
	t.Parallel()

	t.Run("appends the proxy URL suffix and merges queries, keeping body and client headers", func(t *testing.T) {
		t.Parallel()
		s := startStack(t, stackOptions{})

		res := s.send(http.MethodPost, "/ping?x=1&y=2", H{"X-Proxy-Target": s.mock.URL + "?a=1", "X-Client": "kept"}, "hello")

		var payload struct{ Body string }
		if err := json.Unmarshal(res.body, &payload); err != nil || payload.Body != "hello" {
			t.Fatalf("response = %s (%v)", res.body, err)
		}
		seen := s.mock.last(t)
		if seen.URL != "/mcp/ping?a=1&x=1&y=2" {
			t.Errorf("url = %q", seen.URL)
		}
		if got := seen.Header.Get("X-Client"); got != "kept" {
			t.Errorf("x-client = %q", got)
		}
		if want := strings.TrimPrefix(strings.TrimSuffix(s.mock.URL, "/mcp"), "http://"); seen.Host != want {
			t.Errorf("host = %q, want %q", seen.Host, want)
		}
	})

	t.Run("appends a GET path and query to the target", func(t *testing.T) {
		t.Parallel()
		s := startStack(t, stackOptions{})

		s.send(http.MethodGet, "/x/y?z=1", nil, "")

		seen := s.mock.last(t)
		if seen.Method != http.MethodGet || seen.URL != "/mcp/x/y?z=1" {
			t.Errorf("got %s %s", seen.Method, seen.URL)
		}
		if _, ok := seen.Header["Content-Length"]; ok || seen.ContentLength != 0 {
			t.Errorf("a bodiless GET must not carry a content-length (%v)", seen.Header["Content-Length"])
		}
	})

	t.Run("trims trailing slashes of the target path before the suffix", func(t *testing.T) {
		t.Parallel()
		s := startStack(t, stackOptions{})

		s.send(http.MethodGet, "/x", H{"X-Proxy-Target": s.mock.URL + "///?q={{token}}"}, "")

		if got := s.mock.last(t).URL; !strings.HasPrefix(got, "/mcp/x?q=tok.1.") {
			t.Errorf("url = %q", got)
		}
	})

	t.Run("does not append anything for a bare root request", func(t *testing.T) {
		t.Parallel()
		s := startStack(t, stackOptions{})

		s.send(http.MethodPost, "/", H{"X-Proxy-Target": s.mock.URL + "/ping"}, "{}")

		if got := s.mock.last(t).URL; got != "/mcp/ping" {
			t.Errorf("url = %q", got)
		}
	})

	t.Run("does not re-encode an encoded request path", func(t *testing.T) {
		t.Parallel()
		s := startStack(t, stackOptions{})

		s.send(http.MethodGet, "/a%2Fb/c%20d?e=f%26g", nil, "")

		if got := s.mock.last(t).URL; got != "/mcp/a%2Fb/c%20d?e=f%26g" {
			t.Errorf("url = %q", got)
		}
	})

	t.Run("forwards a binary body byte for byte", func(t *testing.T) {
		t.Parallel()
		s := startStack(t, stackOptions{})
		body := make([]byte, 4096)
		_, _ = rand.New(rand.NewSource(1)).Read(body)
		body = append(body, 0x00, 0xff, '\r', '\n')

		s.sendBytes(http.MethodPost, "/ping", nil, body).wantStatus(t, http.StatusOK)

		seen := s.mock.last(t)
		if !bytes.Equal(seen.Body, body) {
			t.Errorf("body differs (%d bytes vs %d)", len(seen.Body), len(body))
		}
		if seen.ContentLength != int64(len(body)) || seen.Header.Get("Content-Length") != strconv.Itoa(len(body)) {
			t.Errorf("content-length = %d / %q", seen.ContentLength, seen.Header.Get("Content-Length"))
		}
	})

	t.Run("sends an explicit content-length of zero for an empty POST", func(t *testing.T) {
		t.Parallel()
		s := startStack(t, stackOptions{})

		s.send(http.MethodPost, "/ping", nil, "").wantStatus(t, http.StatusOK)

		if got := s.mock.last(t).Header.Get("Content-Length"); got != "0" {
			t.Errorf("content-length = %q", got)
		}
	})

	t.Run("streams responses instead of buffering them", func(t *testing.T) {
		t.Parallel()
		s := startStack(t, stackOptions{})
		release := s.mock.holdStream()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		resp := s.stream(ctx, http.MethodGet, "/stream", nil)
		defer resp.Body.Close()
		if ct := resp.Header.Get("Content-Type"); ct != "text/event-stream" {
			t.Errorf("content-type = %q", ct)
		}
		reader := bufio.NewReader(resp.Body)
		line, err := reader.ReadString('\n')
		if err != nil || !strings.Contains(line, "first") {
			t.Fatalf("first event = %q (%v)", line, err)
		}

		release()
		rest, err := io.ReadAll(reader)
		if err != nil || !strings.Contains(string(rest), "second") {
			t.Fatalf("rest = %q (%v)", rest, err)
		}
	})

	t.Run("aborts the upstream request when the client disconnects", func(t *testing.T) {
		t.Parallel()
		s := startStack(t, stackOptions{})
		s.mock.holdStream()
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		resp := s.stream(ctx, http.MethodGet, "/stream", nil)
		line, err := bufio.NewReader(resp.Body).ReadString('\n')
		if err != nil || !strings.Contains(line, "first") {
			t.Fatalf("first event = %q (%v)", line, err)
		}
		cancel()
		resp.Body.Close()

		select {
		case <-s.mock.aborted:
		case <-time.After(5 * time.Second):
			t.Fatal("the upstream request was not aborted after the client left")
		}
	})

	t.Run("returns 502 when the upstream is unreachable", func(t *testing.T) {
		t.Parallel()
		s := startStack(t, stackOptions{})
		s.mock.Close()

		detail := s.ping(nil).wantError(t, http.StatusBadGateway, "upstream_unreachable")

		if want := "cannot reach " + strings.TrimPrefix(s.mock.origin(), "http://") + ": "; !strings.HasPrefix(detail.Message, want) {
			t.Errorf("message = %q, want prefix %q", detail.Message, want)
		}
		if strings.Contains(detail.Message, "tok.") || strings.Contains(s.logs.String(), "tok.") {
			t.Errorf("credential leaked into the error or logs: %q", detail.Message)
		}
	})

	t.Run("passes the response through without decoding or sniffing", func(t *testing.T) {
		t.Parallel()
		s := startStack(t, stackOptions{})

		zipped := s.send(http.MethodGet, "/gzip", H{"Accept-Encoding": "gzip"}, "")
		zipped.wantStatus(t, http.StatusOK)
		if zipped.header.Get("Content-Encoding") != "gzip" || !bytes.Equal(zipped.body, s.mock.gzipBody) {
			t.Errorf("gzip body was altered: %q / %x", zipped.header.Get("Content-Encoding"), zipped.body)
		}
		if got := s.mock.last(t).Header.Get("Accept-Encoding"); got != "gzip" {
			t.Errorf("accept-encoding = %q", got)
		}

		plain := s.send(http.MethodGet, "/notype", nil, "")
		plain.wantStatus(t, http.StatusOK)
		if _, ok := plain.header["Content-Type"]; ok {
			t.Errorf("a content-type was invented: %q", plain.header["Content-Type"])
		}
		if _, ok := s.mock.last(t).Header["Accept-Encoding"]; ok {
			t.Errorf("accept-encoding was added: %q", s.mock.last(t).Header["Accept-Encoding"])
		}
	})

	t.Run("rejects bodies over the limit", func(t *testing.T) {
		t.Parallel()
		s := startStack(t, stackOptions{maxBodyBytes: 16})

		detail := s.send(http.MethodPost, "/ping", nil, strings.Repeat("x", 64)).wantError(t, http.StatusRequestEntityTooLarge, "body_too_large")
		if detail.Message != "request body exceeds 16 bytes" {
			t.Errorf("message = %q", detail.Message)
		}
		wantRequests(t, s, 0)
		wantRuns(t, s, 0)

		s.send(http.MethodPost, "/ping", nil, strings.Repeat("x", 16)).wantStatus(t, http.StatusOK)
	})

	t.Run("answers 413 even when the client keeps sending a large body", func(t *testing.T) {
		t.Parallel()
		s := startStack(t, stackOptions{maxBodyBytes: 16})

		s.sendBytes(http.MethodPost, "/ping", nil, bytes.Repeat([]byte("x"), 200_000)).wantError(t, http.StatusRequestEntityTooLarge, "body_too_large")

		wantRequests(t, s, 0)
	})
}

func TestHeaderHandling(t *testing.T) {
	t.Parallel()

	t.Run("strips control headers and keeps Authorization and Proxy-Authorization", func(t *testing.T) {
		t.Parallel()
		s := startStack(t, stackOptions{})

		s.ping(H{"Authorization": "Basic abc", "X-Proxy-Extra": "foo", "x-PrOxY-other": "bar"}).wantStatus(t, http.StatusOK)

		seen := s.mock.last(t)
		for name := range seen.Header {
			if strings.HasPrefix(strings.ToLower(name), "x-proxy-") {
				t.Errorf("control header %s reached the upstream", name)
			}
		}
		if got := seen.Header.Get("Authorization"); got != "Basic abc" {
			t.Errorf("authorization = %q", got)
		}
		wantTokenSerial(t, seen, 1)
	})

	t.Run("strips hop-by-hop headers from the request and the response", func(t *testing.T) {
		t.Parallel()
		s := startStack(t, stackOptions{})

		res := s.send(http.MethodGet, "/hop", H{
			"Connection":       "X-Hop",
			"X-Hop":            "secret",
			"Keep-Alive":       "timeout=5",
			"Proxy-Connection": "keep-alive",
			"Te":               "trailers",
			"X-Kept":           "yes",
		}, "")

		res.wantStatus(t, http.StatusOK)
		seen := s.mock.last(t)
		for _, name := range []string{"X-Hop", "Keep-Alive", "Proxy-Connection", "Te"} {
			if _, ok := seen.Header[name]; ok {
				t.Errorf("request header %s reached the upstream", name)
			}
		}
		if seen.Header.Get("X-Kept") != "yes" {
			t.Errorf("x-kept = %q", seen.Header.Get("X-Kept"))
		}
		wantTokenSerial(t, seen, 1)
		for _, name := range []string{"X-Resp", "Keep-Alive", "Proxy-Authenticate"} {
			if _, ok := res.header[name]; ok {
				t.Errorf("response header %s reached the client", name)
			}
		}
		if res.header.Get("X-Normal") != "ok" || string(res.body) != "hop" {
			t.Errorf("response = %v / %q", res.header, res.body)
		}
	})

	t.Run("does not invent a User-Agent", func(t *testing.T) {
		t.Parallel()
		s := startStack(t, stackOptions{})

		s.ping(H{"User-Agent": omit}).wantStatus(t, http.StatusOK)
		if ua, ok := s.mock.last(t).Header["User-Agent"]; ok {
			t.Errorf("user-agent = %q, want none", ua)
		}

		s.ping(H{"User-Agent": "custom/1.0"}).wantStatus(t, http.StatusOK)
		if got := s.mock.last(t).Header.Get("User-Agent"); got != "custom/1.0" {
			t.Errorf("user-agent = %q", got)
		}
	})

	t.Run("rejects a credential value with CR or LF before it can reach the upstream", func(t *testing.T) {
		t.Parallel()
		s := startStack(t, stackOptions{genFormat: "crlf"})

		s.ping(nil).wantError(t, http.StatusBadGateway, "auth_command_failed")

		wantRequests(t, s, 0)
	})

	t.Run("forwards spaces and non-ASCII credential values in headers intact", func(t *testing.T) {
		t.Parallel()
		s := startStack(t, stackOptions{genFormat: "multi", tenant: "héllo wörld"})

		s.ping(H{"X-Tenant": "t={{tenant}}"}).wantStatus(t, http.StatusOK)

		if got := s.mock.last(t).Header.Get("X-Tenant"); got != "t=héllo wörld" {
			t.Errorf("x-tenant = %q", got)
		}
	})
}

func TestLocalSafety(t *testing.T) {
	t.Parallel()

	t.Run("rejects browser requests and foreign Host headers without touching the upstream", func(t *testing.T) {
		t.Parallel()
		s := startStack(t, stackOptions{})
		port := strconv.Itoa(s.proxy.Port)

		s.send(http.MethodGet, "/ping", H{"Origin": "https://evil.example"}, "").wantError(t, http.StatusForbidden, "forbidden_origin")
		s.send(http.MethodGet, "/ping", H{"Origin": ""}, "").wantError(t, http.StatusForbidden, "forbidden_origin")
		for _, host := range []string{"evil.example", "127.0.0.1", "localhost:" + strconv.Itoa(s.proxy.Port+1), "127.0.0.1.evil.example:" + port} {
			s.send(http.MethodGet, "/ping", H{"Host": host}, "").wantError(t, http.StatusForbidden, "forbidden_host")
		}

		wantRequests(t, s, 0)
		wantRuns(t, s, 0)
	})

	t.Run("checks the Host header before the Origin header", func(t *testing.T) {
		t.Parallel()
		s := startStack(t, stackOptions{})

		s.bare(http.MethodGet, "/_health", H{"Host": "evil.example", "Origin": "https://evil.example"}).wantError(t, http.StatusForbidden, "forbidden_host")
	})

	t.Run("accepts loopback names at the bound port in any case", func(t *testing.T) {
		t.Parallel()
		s := startStack(t, stackOptions{})
		port := strconv.Itoa(s.proxy.Port)

		for _, host := range []string{"127.0.0.1:" + port, "localhost:" + port, "LOCALHOST:" + port, "[::1]:" + port} {
			s.bare(http.MethodGet, "/_health", H{"Host": host}).wantStatus(t, http.StatusOK)
		}
	})

	t.Run("reports health without exposing credentials", func(t *testing.T) {
		t.Parallel()
		s := startStack(t, stackOptions{})
		s.ping(nil)

		health := s.bare(http.MethodGet, "/_health", nil)

		health.wantStatus(t, http.StatusOK)
		if ct := health.header.Get("Content-Type"); ct != "application/json" {
			t.Errorf("content-type = %q", ct)
		}
		if strings.Contains(string(health.body), "tok.") {
			t.Errorf("health leaks a credential: %s", health.body)
		}
		var parsed struct {
			OK         bool
			Strategies map[string]struct {
				AllowedHosts []string
				Auth         struct{ HasCredentials bool }
			}
		}
		if err := json.Unmarshal(health.body, &parsed); err != nil {
			t.Fatal(err)
		}
		up := parsed.Strategies["up"]
		if !parsed.OK || !up.Auth.HasCredentials || !reflect.DeepEqual(up.AllowedHosts, []string{s.mock.origin()}) {
			t.Errorf("health = %s", health.body)
		}
	})

	t.Run("never logs credential values or rendered URLs", func(t *testing.T) {
		t.Parallel()
		s := startStack(t, stackOptions{genFormat: "multi"})
		s.ping(H{
			"X-Proxy-Target": s.mock.URL + "/ping?access_token={{token}}&t={{tenant}}",
			"X-Tenant":       "{{tenant}}",
		})
		s.mock.setRejectAll(true)
		s.ping(nil)

		logs := s.logs.String()

		if regexp.MustCompile(`tok\.\d+\.`).MatchString(logs) || strings.Contains(logs, "acme") || strings.Contains(logs, "access_token") {
			t.Errorf("logs contain credential material:\n%s", logs)
		}
		debugLine := regexp.MustCompile(`DEBUG \[up\] POST ` + regexp.QuoteMeta(strings.TrimPrefix(s.mock.origin(), "http://")) + `/mcp/ping -> 200 in \d+ms`)
		if !debugLine.MatchString(logs) {
			t.Errorf("no per-request debug line in logs:\n%s", logs)
		}
		if !strings.Contains(logs, "upstream answered 401; retrying once with fresh credentials") {
			t.Errorf("no retry line in logs:\n%s", logs)
		}
	})
}

func TestLifecycle(t *testing.T) {
	t.Parallel()

	t.Run("warns when bound to a non-loopback address", func(t *testing.T) {
		t.Parallel()
		s := startStack(t, stackOptions{listenHost: "0.0.0.0"})

		want := "WARN  listening on non-loopback address 0.0.0.0; anything that can reach it can use your credentials"
		if !strings.Contains(s.logs.String(), want) {
			t.Errorf("logs:\n%s", s.logs.String())
		}
		if want := "http://0.0.0.0:" + strconv.Itoa(s.proxy.Port) + "/"; s.proxy.URL != want {
			t.Errorf("url = %q, want %q", s.proxy.URL, want)
		}
		s.bare(http.MethodGet, "/_health", H{"Host": "0.0.0.0:" + strconv.Itoa(s.proxy.Port)}).wantStatus(t, http.StatusOK)
	})

	t.Run("does not warn on a loopback address and exposes its providers", func(t *testing.T) {
		t.Parallel()
		s := startStack(t, stackOptions{})

		if strings.Contains(s.logs.String(), "non-loopback") {
			t.Errorf("unexpected warning:\n%s", s.logs.String())
		}
		if s.proxy.Host != "127.0.0.1" || s.proxy.Port == 0 || s.proxy.Providers["up"] == nil {
			t.Errorf("running = %+v", s.proxy)
		}
		if want := "http://127.0.0.1:" + strconv.Itoa(s.proxy.Port) + "/"; s.proxy.URL != want {
			t.Errorf("url = %q", s.proxy.URL)
		}
		s.ping(nil)
		if got := s.proxy.Providers["up"].Status(); !got.HasCredentials {
			t.Errorf("provider status = %+v", got)
		}
	})

	t.Run("brackets IPv6 hosts in the URL and accepts them as Host", func(t *testing.T) {
		t.Parallel()
		mock := startMockUpstream(t, false, "")
		ln, err := net.Listen("tcp", "[::1]:0")
		if err != nil {
			t.Skipf("no IPv6 loopback: %v", err)
		}
		_ = ln.Close()
		cfg := buildConfig(t, stackOptions{listenHost: "::1"}, mock.origin())
		running, err := Start(Options{Config: cfg})
		if err != nil {
			t.Fatalf("Start failed: %v", err)
		}
		t.Cleanup(func() { _ = running.Close(context.Background()) })

		if want := "http://[::1]:" + strconv.Itoa(running.Port) + "/"; running.URL != want {
			t.Errorf("url = %q, want %q", running.URL, want)
		}
		resp, err := http.Get(running.URL + "_health")
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("status = %d", resp.StatusCode)
		}
	})

	t.Run("fails to start when the port is taken", func(t *testing.T) {
		t.Parallel()
		s := startStack(t, stackOptions{})
		cfg := buildConfig(t, stackOptions{}, s.mock.origin())
		cfg.Listen.Port = s.proxy.Port

		if running, err := Start(Options{Config: cfg}); err == nil {
			_ = running.Close(context.Background())
			t.Fatal("Start succeeded on a busy port")
		}
	})

	t.Run("rejects a missing config and an invalid allowedHosts entry", func(t *testing.T) {
		t.Parallel()
		if _, err := Start(Options{}); err == nil {
			t.Error("Start accepted a nil config")
		}
		cfg := buildConfig(t, stackOptions{}, "http://127.0.0.1:1")
		strategy := cfg.Strategies["up"]
		strategy.AllowedHosts = []string{"not a host"}
		cfg.Strategies["up"] = strategy
		if _, err := Start(Options{Config: cfg}); err == nil {
			t.Error("Start accepted an invalid allowedHosts entry")
		}
	})

	t.Run("close force-closes streams that outlive the deadline", func(t *testing.T) {
		t.Parallel()
		s := startStack(t, stackOptions{})
		s.mock.holdStream()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		resp := s.stream(ctx, http.MethodGet, "/stream", nil)
		defer resp.Body.Close()
		reader := bufio.NewReader(resp.Body)
		if _, err := reader.ReadString('\n'); err != nil {
			t.Fatal(err)
		}

		closeCtx, closeCancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer closeCancel()
		if err := s.proxy.Close(closeCtx); err != nil {
			t.Errorf("Close returned %v", err)
		}

		_, _ = io.Copy(io.Discard, reader)
		select {
		case <-s.mock.aborted:
		case <-time.After(5 * time.Second):
			t.Fatal("the upstream request was not aborted by Close")
		}
	})
}
