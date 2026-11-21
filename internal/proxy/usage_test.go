package proxy

import (
	"io"
	"strings"
	"testing"
	"testing/iotest"
)

func TestUsageReader(t *testing.T) {
	sse := "event: message_start\r\ndata: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":12,\"cache_creation_input_tokens\":3}}}\r\n\r\n" +
		"event: ping\ndata: {\"type\":\"ping\"}\n\n" +
		"data: {\"type\":\"content_block_delta\",\"delta\":{\"text\":\"\\\"usage\\\": fake\"}}\n\n" +
		"data: " + strings.Repeat("x", maxLine+10) + "\n" +
		"event: message_delta\ndata: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":99}}"
	var got Usage
	// One byte at a time: lines split across reads must still parse.
	r := newUsageReader(io.NopCloser(iotest.OneByteReader(strings.NewReader(sse))), true, func(u Usage) { got = u })
	out, err := io.ReadAll(r)
	if err != nil || string(out) != sse {
		t.Fatalf("body changed: %v", err)
	}
	r.Close()
	if got != (Usage{InputTokens: 12, OutputTokens: 99, CacheCreationInputTokens: 3}) {
		t.Errorf("sse usage %+v", got)
	}

	got = Usage{}
	r = newUsageReader(io.NopCloser(strings.NewReader(`{"id":"m","usage":{"input_tokens":5,"output_tokens":6,"cache_read_input_tokens":2}}`)), false, func(u Usage) { got = u })
	io.ReadAll(r)
	r.Close()
	if got != (Usage{InputTokens: 5, OutputTokens: 6, CacheReadInputTokens: 2}) {
		t.Errorf("json usage %+v", got)
	}
}
