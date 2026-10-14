package logger

import (
	"fmt"
	"io"
	"os"
	"regexp"
	"time"
)

type Logger interface {
	Debug(format string, args ...any)
	Info(format string, args ...any)
	Warn(format string, args ...any)
	Error(format string, args ...any)
}

type writerLogger struct {
	debug bool
	out   func(line string)
}

// New writes "<RFC3339 ms> LEVEL message\n" lines. A nil writer means stderr.
func New(debug bool, w io.Writer) Logger {
	if w == nil {
		w = os.Stderr
	}
	return &writerLogger{debug: debug, out: func(line string) { _, _ = io.WriteString(w, line) }}
}

func (l *writerLogger) emit(tag, format string, args []any) {
	l.out(fmt.Sprintf("%s %s %s\n", time.Now().UTC().Format("2006-01-02T15:04:05.000Z"), tag, fmt.Sprintf(format, args...)))
}

func (l *writerLogger) Debug(format string, args ...any) {
	if l.debug {
		l.emit("DEBUG", format, args)
	}
}
func (l *writerLogger) Info(format string, args ...any)  { l.emit("INFO ", format, args) }
func (l *writerLogger) Warn(format string, args ...any)  { l.emit("WARN ", format, args) }
func (l *writerLogger) Error(format string, args ...any) { l.emit("ERROR", format, args) }

type silent struct{}

func (silent) Debug(string, ...any) {}
func (silent) Info(string, ...any)  {}
func (silent) Warn(string, ...any)  {}
func (silent) Error(string, ...any) {}

var Silent Logger = silent{}

var (
	jwtPattern    = regexp.MustCompile(`eyJ[\w-]+\.[\w-]+\.[\w-]*`)
	bearerPattern = regexp.MustCompile(`(?i)\b(Bearer|Basic)\s+\S+`)
)

// Redact hides JWTs and Bearer/Basic credentials in text destined for logs or error messages.
func Redact(text string) string {
	text = jwtPattern.ReplaceAllString(text, "<jwt>")
	return bearerPattern.ReplaceAllString(text, "$1 <redacted>")
}
