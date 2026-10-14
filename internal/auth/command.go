package auth

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/Oudwins/mcp-auth-proxy/internal/config"
	"github.com/Oudwins/mcp-auth-proxy/internal/logger"
)

const (
	maxStdoutBytes       = 1024 * 1024
	maxStderrChars       = 2000
	maxStderrDetailChars = 400
	// bounds how long a grandchild that inherited our pipes can delay the call after the command exits
	waitDelay = 500 * time.Millisecond
)

// CommandError is a failure of the auth command or its output; the proxy maps it to 502 auth_command_failed.
// The package always returns *CommandError.
type CommandError struct{ Message string }

func (e CommandError) Error() string { return e.Message }

func commandErrorf(format string, args ...any) error {
	return &CommandError{Message: fmt.Sprintf(format, args...)}
}

// Context is the run context exported to the command as MCP_AUTH_PROXY_STRATEGY and MCP_AUTH_PROXY_FORCE_REFRESH.
type Context struct {
	Strategy string
	Forced   bool
}

type cappedBuffer struct {
	buf      bytes.Buffer
	limit    int
	exceeded bool
	onExceed func()
}

func (c *cappedBuffer) Write(p []byte) (int, error) {
	if c.exceeded {
		return len(p), nil
	}
	room := c.limit - c.buf.Len()
	if len(p) > room {
		c.buf.Write(p[:room])
		c.exceeded = true
		c.onExceed()
		return len(p), nil
	}
	return c.buf.Write(p)
}

type tailBuffer struct {
	data  []byte
	limit int
}

func (t *tailBuffer) Write(p []byte) (int, error) {
	t.data = append(t.data, p...)
	if len(t.data) > t.limit {
		t.data = append([]byte(nil), t.data[len(t.data)-t.limit:]...)
	}
	return len(p), nil
}

func (t *tailBuffer) String(chars int) string {
	data := t.data
	for len(data) > 0 && !utf8.RuneStart(data[0]) {
		data = data[1:]
	}
	return lastRunes(string(bytes.ToValidUTF8(data, []byte("\ufffd"))), chars)
}

func lastRunes(s string, n int) string {
	runes := []rune(s)
	if len(runes) > n {
		runes = runes[len(runes)-n:]
	}
	return string(runes)
}

func killGroup(cmd *exec.Cmd) error {
	if cmd.Process == nil {
		return os.ErrProcessDone
	}
	err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	if err == nil {
		return nil
	}
	if errors.Is(err, syscall.ESRCH) {
		return os.ErrProcessDone
	}
	return cmd.Process.Kill()
}

func buildEnv(s config.Strategy, rc Context) []string {
	env := os.Environ()
	keys := make([]string, 0, len(s.Env))
	for key := range s.Env {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		env = append(env, key+"="+s.Env[key])
	}
	forced := "0"
	if rc.Forced {
		forced = "1"
	}
	return append(env, "MCP_AUTH_PROXY_STRATEGY="+rc.Strategy, "MCP_AUTH_PROXY_FORCE_REFRESH="+forced)
}

func formatSeconds(d time.Duration) string {
	return strconv.FormatFloat(d.Seconds(), 'f', -1, 64) + "s"
}

func interrupted(ctx context.Context, timeout time.Duration) error {
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return commandErrorf("auth command timed out after %s", formatSeconds(timeout))
	}
	return commandErrorf("auth command was cancelled")
}

func signalName(sig syscall.Signal) string {
	names := map[syscall.Signal]string{
		syscall.SIGHUP:  "SIGHUP",
		syscall.SIGINT:  "SIGINT",
		syscall.SIGQUIT: "SIGQUIT",
		syscall.SIGABRT: "SIGABRT",
		syscall.SIGKILL: "SIGKILL",
		syscall.SIGSEGV: "SIGSEGV",
		syscall.SIGPIPE: "SIGPIPE",
		syscall.SIGALRM: "SIGALRM",
		syscall.SIGTERM: "SIGTERM",
	}
	if name, ok := names[sig]; ok {
		return name
	}
	return "signal " + strconv.Itoa(int(sig))
}

// Run executes the strategy command and returns its stdout. The command and every process it
// spawned in its process group are killed when the strategy timeout or ctx ends.
func Run(ctx context.Context, s config.Strategy, rc Context) (string, error) {
	if len(s.Command) == 0 {
		return "", commandErrorf("could not start auth command: empty command")
	}
	if s.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, s.Timeout)
		defer cancel()
	}

	cmd := exec.CommandContext(ctx, s.Command[0], s.Command[1:]...)
	stdout := &cappedBuffer{limit: maxStdoutBytes, onExceed: func() { _ = killGroup(cmd) }}
	stderr := &tailBuffer{limit: maxStderrChars * utf8.UTFMax}
	cmd.Dir = s.Cwd
	cmd.Env = buildEnv(s, rc)
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return killGroup(cmd) }
	cmd.WaitDelay = waitDelay

	if err := cmd.Start(); err != nil {
		if ctx.Err() != nil {
			return "", interrupted(ctx, s.Timeout)
		}
		return "", commandErrorf("could not start auth command: %v", err)
	}
	err := cmd.Wait()

	switch {
	case stdout.exceeded:
		return "", commandErrorf("auth command printed more than %d bytes to stdout", maxStdoutBytes)
	case err != nil && ctx.Err() != nil:
		return "", interrupted(ctx, s.Timeout)
	case err == nil || errors.Is(err, exec.ErrWaitDelay):
		return stdout.buf.String(), nil
	}

	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		return "", commandErrorf("auth command failed: %v", err)
	}
	how := fmt.Sprintf("exited with code %d", exitErr.ExitCode())
	if status, ok := exitErr.Sys().(syscall.WaitStatus); ok && status.Signaled() {
		how = "was killed by " + signalName(status.Signal())
	}
	detail := lastRunes(logger.Redact(trimJS(stderr.String(maxStderrChars))), maxStderrDetailChars)
	if detail != "" {
		return "", commandErrorf("auth command %s: %s", how, detail)
	}
	return "", commandErrorf("auth command %s", how)
}
