package proxy

import (
	"bytes"
	"encoding/json"
	"io"
	"sync"
)

// Usage is the token accounting of one Messages response.
type Usage struct {
	InputTokens              int64 `json:"input_tokens"`
	OutputTokens             int64 `json:"output_tokens"`
	CacheCreationInputTokens int64 `json:"cache_creation_input_tokens"`
	CacheReadInputTokens     int64 `json:"cache_read_input_tokens"`
}

func (u *Usage) merge(o Usage) {
	u.InputTokens = max(u.InputTokens, o.InputTokens)
	u.OutputTokens = max(u.OutputTokens, o.OutputTokens)
	u.CacheCreationInputTokens = max(u.CacheCreationInputTokens, o.CacheCreationInputTokens)
	u.CacheReadInputTokens = max(u.CacheReadInputTokens, o.CacheReadInputTokens)
}

const maxLine = 1 << 20

// usageReader passes a response body through unchanged and picks the usage
// out of it on the way: from the message_start and message_delta events of
// a stream, or from the top-level "usage" of a JSON body. It never keeps
// more than one line (stream) or maxLine bytes (JSON) and records nothing
// else from the body.
type usageReader struct {
	r     io.ReadCloser
	sse   bool
	buf   []byte
	skip  bool // current line is over maxLine
	once  sync.Once
	done  func(Usage)
	usage Usage
}

func newUsageReader(r io.ReadCloser, sse bool, done func(Usage)) *usageReader {
	return &usageReader{r: r, sse: sse, done: done}
}

func (u *usageReader) Read(p []byte) (int, error) {
	n, err := u.r.Read(p)
	u.observe(p[:n])
	if err == io.EOF {
		u.finish()
	}
	return n, err
}

func (u *usageReader) Close() error {
	err := u.r.Close()
	u.finish()
	return err
}

func (u *usageReader) finish() {
	u.once.Do(func() {
		if u.sse {
			u.line(u.buf)
		} else if !u.skip {
			u.json(u.buf)
		}
		u.buf = nil
		u.done(u.usage)
	})
}

func (u *usageReader) observe(b []byte) {
	if !u.sse {
		if u.skip {
			return
		}
		if len(u.buf)+len(b) > maxLine {
			u.skip, u.buf = true, nil
			return
		}
		u.buf = append(u.buf, b...)
		return
	}
	for len(b) > 0 {
		i := bytes.IndexByte(b, '\n')
		if i < 0 {
			u.appendLine(b)
			return
		}
		u.appendLine(b[:i])
		if !u.skip {
			u.line(u.buf)
		}
		u.buf, u.skip = u.buf[:0], false
		b = b[i+1:]
	}
}

func (u *usageReader) appendLine(b []byte) {
	if u.skip {
		return
	}
	if len(u.buf)+len(b) > maxLine {
		u.skip, u.buf = true, u.buf[:0]
		return
	}
	u.buf = append(u.buf, b...)
}

func (u *usageReader) line(l []byte) {
	l = bytes.TrimRight(l, "\r")
	data, ok := bytes.CutPrefix(l, []byte("data:"))
	if !ok || !bytes.Contains(data, []byte(`"usage"`)) {
		return
	}
	var ev struct {
		Type    string `json:"type"`
		Usage   *Usage `json:"usage"`
		Message struct {
			Usage *Usage `json:"usage"`
		} `json:"message"`
	}
	if json.Unmarshal(bytes.TrimSpace(data), &ev) != nil {
		return
	}
	switch ev.Type {
	case "message_start":
		if ev.Message.Usage != nil {
			u.usage.merge(*ev.Message.Usage)
		}
	case "message_delta":
		if ev.Usage != nil {
			u.usage.merge(*ev.Usage)
		}
	}
}

func (u *usageReader) json(b []byte) {
	var m struct {
		Usage *Usage `json:"usage"`
	}
	if json.Unmarshal(b, &m) == nil && m.Usage != nil {
		u.usage.merge(*m.Usage)
	}
}
