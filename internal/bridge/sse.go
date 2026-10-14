package bridge

import (
	"bufio"
	"errors"
	"io"
	"strings"
)

type sseEvent struct {
	Event string
	Data  string
	ID    string
}

// readSSE calls fn for every event that carries data or an id. A trailing event without a blank line is flushed at EOF.
func readSSE(r io.Reader, fn func(sseEvent)) error {
	br := bufio.NewReader(r)
	var (
		ev    sseEvent
		data  []string
		idSet bool
		first = true
	)

	dispatch := func() {
		if len(data) > 0 || idSet {
			ev.Data = strings.Join(data, "\n")
			fn(ev)
		}
		ev = sseEvent{}
		data = nil
		idSet = false
	}

	process := func(line string) {
		if first {
			line = strings.TrimPrefix(line, "\uFEFF")
			first = false
		}
		if line == "" {
			dispatch()
			return
		}
		if line[0] == ':' {
			return
		}
		field, value, _ := strings.Cut(line, ":")
		value = strings.TrimPrefix(value, " ")
		switch field {
		case "data":
			data = append(data, value)
		case "event":
			ev.Event = value
		case "id":
			if !strings.ContainsRune(value, 0) {
				ev.ID = value
				idSet = true
			}
		}
	}

	for {
		line, err := br.ReadString('\n')
		if line != "" {
			line = strings.TrimSuffix(line, "\n")
			line = strings.TrimSuffix(line, "\r")
			process(line)
		}
		if err != nil {
			dispatch()
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
	}
}
