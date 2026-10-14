package auth

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/Oudwins/mcp-auth-proxy/internal/config"
)

var payloadContext = Context{Strategy: "payload", Forced: false}

func shell(script string) func(*config.Strategy) {
	return func(s *config.Strategy) { s.Command = []string{"/bin/sh", "-c", script} }
}

func realTempDir(t *testing.T) string {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return dir
}

func runOK(t *testing.T, s config.Strategy, rc Context) string {
	t.Helper()
	stdout, err := Run(context.Background(), s, rc)
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	return stdout
}

func runErr(t *testing.T, s config.Strategy, rc Context) string {
	t.Helper()
	_, err := Run(context.Background(), s, rc)
	if err == nil {
		t.Fatal("Run succeeded, expected an error")
	}
	var ce *CommandError
	if !errors.As(err, &ce) {
		t.Fatalf("error %T is not a *CommandError", err)
	}
	return err.Error()
}

func readPid(t *testing.T, file string) int {
	t.Helper()
	raw, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(raw)))
	if err != nil {
		t.Fatal(err)
	}
	return pid
}

func waitForExit(t *testing.T, pid int) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if err := syscall.Kill(pid, 0); err != nil {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	_ = syscall.Kill(pid, syscall.SIGKILL)
	t.Fatalf("process %d is still alive", pid)
}

func TestRunOutput(t *testing.T) {
	tests := []struct {
		name string
		s    config.Strategy
		rc   Context
		want string
	}{
		{"string commands run through the shell", makeStrategy(shell("echo hello | tr a-z A-Z")), payloadContext, "HELLO\n"},
		{"array commands exec without shell expansion", makeStrategy(func(s *config.Strategy) { s.Command = []string{"printf", "%s", "$HOME"} }), payloadContext, "$HOME"},
		{
			"strategy context and configured env",
			makeStrategy(shell(`printf '%s|%s|%s' "$MCP_AUTH_PROXY_STRATEGY" "$MCP_AUTH_PROXY_FORCE_REFRESH" "$FOO"`), func(s *config.Strategy) { s.Env = map[string]string{"FOO": "bar"} }),
			Context{Strategy: "payload", Forced: true},
			"payload|1|bar",
		},
		{"force refresh flag is 0 when not forced", makeStrategy(shell(`printf '%s' "$MCP_AUTH_PROXY_FORCE_REFRESH"`)), payloadContext, "0"},
		{"removed upstream variables are not provided", makeStrategy(shell(`printf '%s|%s' "${MCP_AUTH_PROXY_UPSTREAM-unset}" "${MCP_AUTH_PROXY_UPSTREAM_URL-unset}"`)), payloadContext, "unset|unset"},
		{"stdout of exactly the cap is accepted", makeStrategy(shell("head -c 1048576 /dev/zero | tr '\\0' 'a'")), payloadContext, strings.Repeat("a", 1024*1024)},
		{"stdin is empty", makeStrategy(shell("cat; printf done")), payloadContext, "done"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := runOK(t, tt.s, tt.rc); got != tt.want {
				t.Errorf("stdout = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestRunEnvironment(t *testing.T) {
	t.Run("inherits the proxy environment", func(t *testing.T) {
		t.Setenv("AUTH_TEST_INHERITED", "from-parent")
		got := runOK(t, makeStrategy(shell(`printf '%s' "$AUTH_TEST_INHERITED"`)), payloadContext)
		if got != "from-parent" {
			t.Errorf("stdout = %q", got)
		}
	})

	t.Run("strategy env overrides the proxy environment", func(t *testing.T) {
		t.Setenv("AUTH_TEST_OVERRIDE", "from-parent")
		s := makeStrategy(shell(`printf '%s' "$AUTH_TEST_OVERRIDE"`), func(s *config.Strategy) {
			s.Env = map[string]string{"AUTH_TEST_OVERRIDE": "from-strategy"}
		})
		if got := runOK(t, s, payloadContext); got != "from-strategy" {
			t.Errorf("stdout = %q", got)
		}
	})

	t.Run("context variables override strategy env and proxy environment", func(t *testing.T) {
		t.Setenv("MCP_AUTH_PROXY_STRATEGY", "parent")
		s := makeStrategy(shell(`printf '%s|%s' "$MCP_AUTH_PROXY_STRATEGY" "$MCP_AUTH_PROXY_FORCE_REFRESH"`), func(s *config.Strategy) {
			s.Env = map[string]string{"MCP_AUTH_PROXY_STRATEGY": "strategy", "MCP_AUTH_PROXY_FORCE_REFRESH": "9"}
		})
		if got := runOK(t, s, Context{Strategy: "real", Forced: true}); got != "real|1" {
			t.Errorf("stdout = %q", got)
		}
	})

	t.Run("runs in the configured working directory", func(t *testing.T) {
		dir := realTempDir(t)
		got := runOK(t, makeStrategy(shell("pwd"), func(s *config.Strategy) { s.Cwd = dir }), payloadContext)
		if strings.TrimSpace(got) != dir {
			t.Errorf("pwd = %q, want %q", got, dir)
		}
	})
}

func TestRunFailures(t *testing.T) {
	t.Run("reports the exit code and a redacted stderr tail", func(t *testing.T) {
		s := makeStrategy(shell(`echo "Reauthentication needed, Bearer abcdef.ghijkl.mnopqr rejected" >&2; exit 3`))
		message := runErr(t, s, payloadContext)
		expectMatch(t, message, "exited with code 3")
		expectMatch(t, message, "Reauthentication needed")
		if strings.Contains(message, "abcdef.ghijkl") {
			t.Errorf("message %q leaks the credential", message)
		}
	})

	t.Run("redacts JWTs in stderr", func(t *testing.T) {
		message := runErr(t, makeStrategy(shell("echo token eyJhbGciOi.eyJleHAiOjF9.sig >&2; exit 1")), payloadContext)
		if strings.Contains(message, "eyJhbGciOi") {
			t.Errorf("message %q leaks the JWT", message)
		}
	})

	t.Run("omits the detail when stderr is empty", func(t *testing.T) {
		if message := runErr(t, makeStrategy(shell("exit 4")), payloadContext); message != "auth command exited with code 4" {
			t.Errorf("message = %q", message)
		}
	})

	t.Run("keeps only the last 400 characters of stderr", func(t *testing.T) {
		message := runErr(t, makeStrategy(shell(`printf 'START' >&2; head -c 5000 /dev/zero | tr '\0' x >&2; exit 1`)), payloadContext)
		prefix := "auth command exited with code 1: "
		if !strings.HasPrefix(message, prefix) || len(message)-len(prefix) != 400 {
			t.Errorf("message has %d detail chars: %q", len(message)-len(prefix), message)
		}
		if strings.Contains(message, "START") {
			t.Errorf("message %q kept the head of stderr", message)
		}
	})

	t.Run("reports a command killed by a signal", func(t *testing.T) {
		expectMatch(t, runErr(t, makeStrategy(shell("kill -9 $$")), payloadContext), "was killed by SIGKILL")
	})

	t.Run("reports a command that cannot be started", func(t *testing.T) {
		s := makeStrategy(func(s *config.Strategy) { s.Command = []string{"/nonexistent/binary"} })
		expectMatch(t, runErr(t, s, payloadContext), "could not start auth command")
	})

	t.Run("reports a working directory that does not exist", func(t *testing.T) {
		s := makeStrategy(shell("true"), func(s *config.Strategy) { s.Cwd = "/nonexistent/dir" })
		expectMatch(t, runErr(t, s, payloadContext), "could not start auth command")
	})

	t.Run("reports an empty command", func(t *testing.T) {
		s := makeStrategy(func(s *config.Strategy) { s.Command = nil })
		expectMatch(t, runErr(t, s, payloadContext), "could not start auth command")
	})

	t.Run("errors when stdout exceeds the cap and stops the command", func(t *testing.T) {
		start := time.Now()
		message := runErr(t, makeStrategy(shell("head -c 3000000 /dev/zero | tr '\\0' 'a'; sleep 30")), payloadContext)
		expectMatch(t, message, "more than 1048576 bytes")
		if elapsed := time.Since(start); elapsed > 5*time.Second {
			t.Errorf("took %v", elapsed)
		}
	})
}

func TestRunTimeoutAndCancellation(t *testing.T) {
	t.Run("kills the command and its children on timeout", func(t *testing.T) {
		dir := realTempDir(t)
		pidFile := filepath.Join(dir, "pid")
		s := makeStrategy(shell(`sleep 30 & echo $! > "`+pidFile+`"; wait`), func(s *config.Strategy) {
			s.Timeout = 500 * time.Millisecond
			s.Cwd = dir
		})

		start := time.Now()
		expectMatch(t, runErr(t, s, payloadContext), "timed out after 0.5s")
		if elapsed := time.Since(start); elapsed > 3*time.Second {
			t.Errorf("took %v", elapsed)
		}
		waitForExit(t, readPid(t, pidFile))
	})

	t.Run("formats whole second timeouts without decimals", func(t *testing.T) {
		if got := formatSeconds(30 * time.Second); got != "30s" {
			t.Errorf("formatSeconds = %q", got)
		}
	})

	t.Run("a grandchild holding the stdout pipe cannot hang the call", func(t *testing.T) {
		dir := realTempDir(t)
		pidFile := filepath.Join(dir, "pid")
		s := makeStrategy(shell(`sleep 30 & echo $! > "`+pidFile+`"; echo token`), func(s *config.Strategy) { s.Cwd = dir })

		start := time.Now()
		got := runOK(t, s, payloadContext)
		elapsed := time.Since(start)
		_ = syscall.Kill(readPid(t, pidFile), syscall.SIGKILL)

		if got != "token\n" {
			t.Errorf("stdout = %q", got)
		}
		if elapsed > 3*time.Second {
			t.Errorf("took %v", elapsed)
		}
	})

	t.Run("a grandchild holding the pipe cannot extend a timeout", func(t *testing.T) {
		s := makeStrategy(shell("sleep 30 & sleep 30"), func(s *config.Strategy) { s.Timeout = 300 * time.Millisecond })

		start := time.Now()
		expectMatch(t, runErr(t, s, payloadContext), "timed out")
		if elapsed := time.Since(start); elapsed > 3*time.Second {
			t.Errorf("took %v", elapsed)
		}
	})

	t.Run("cancelling the context kills the command", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		time.AfterFunc(150*time.Millisecond, cancel)

		start := time.Now()
		_, err := Run(ctx, makeStrategy(shell("sleep 30")), payloadContext)
		if err == nil || !strings.Contains(err.Error(), "cancelled") {
			t.Errorf("err = %v", err)
		}
		if elapsed := time.Since(start); elapsed > 3*time.Second {
			t.Errorf("took %v", elapsed)
		}
	})

	t.Run("an already cancelled context does not start the command", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, err := Run(ctx, makeStrategy(shell("true")), payloadContext)
		if err == nil || !strings.Contains(err.Error(), "cancelled") {
			t.Errorf("err = %v", err)
		}
	})
}
