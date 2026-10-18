package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/Harsette/ralx/internal/client"
)

// Hosted MCP uses the Worker's native stateless HTTP protocol. Identity keys
// stay in the private identity file, never in config arguments or stdout.
func cmdCloudMCP(ctx context.Context) error {
	id, e := client.ReadIdentity(client.KeyFile())
	if e != nil {
		return e
	}
	if id.URL == "" {
		return errors.New("hosted identity needs an origin")
	}
	scanner := bufio.NewScanner(os.Stdin)
	httpClient := &http.Client{Timeout: 90 * time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	scanner.Buffer(make([]byte, 4096), 4<<20)
	for scanner.Scan() {
		line := scanner.Bytes()
		var req struct {
			ID json.RawMessage `json:"id"`
		}
		if e := json.Unmarshal(line, &req); e != nil {
			return e
		}
		r, e := http.NewRequestWithContext(ctx, "POST", id.URL+"/mcp", bytes.NewReader(line))
		if e != nil {
			return e
		}
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Accept", "application/json, text/event-stream")
		r.Header.Set("Authorization", "Bearer "+id.Key)
		resp, e := httpClient.Do(r)
		if e != nil {
			return errors.New("hosted MCP unavailable; run ralx doctor")
		}
		b, e := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
		resp.Body.Close()
		if e != nil {
			return e
		}
		if len(req.ID) == 0 {
			continue
		}
		if resp.StatusCode != 200 || !json.Valid(b) {
			return errors.New("hosted MCP refused the request; run ralx doctor")
		}
		var compact bytes.Buffer
		if e := json.Compact(&compact, b); e != nil {
			return e
		}
		if _, e := os.Stdout.Write(append(compact.Bytes(), '\n')); e != nil {
			return e
		}
	}
	return scanner.Err()
}
