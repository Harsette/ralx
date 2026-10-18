package daemon

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
)

const agentOutputCap = 64 << 20

// agentOutput covers SDK-owned responses, callbacks, headers and downloads at
// serialization. Ordinary responses are bounded and checked whole; SSE is checked
// as complete events, never as arbitrary Write chunks. Admin reveal is excluded.
func (s *Server) agentOutput(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		out := &agentWriter{s: s, dst: w, header: w.Header().Clone()}
		// Identity is used only for session-output filtering; route auth still runs.
		fields := strings.Fields(r.Header.Get("Authorization"))
		if len(fields) == 2 && strings.EqualFold(fields[0], "Bearer") {
			if agent, _, resource, _, err := s.authenticateBearer(fields[1]); err == nil && s.checkAudience(resource, r) == nil {
				out.actor = agent.ID
			}
		}
		out.catalogREST, out.catalogID = catalogRequest(r)
		next.ServeHTTP(out, r)
		out.finish()
	})
}

type agentWriter struct {
	actor            string
	catalogREST      bool
	catalogID        json.RawMessage
	s                *Server
	dst              http.ResponseWriter
	header           http.Header
	buf              bytes.Buffer
	code             int
	started, stopped bool
}

func (w *agentWriter) Header() http.Header { return w.header }
func (w *agentWriter) WriteHeader(code int) {
	if w.code == 0 {
		w.code = code
	}
}
func (w *agentWriter) Write(b []byte) (int, error) {
	if w.stopped {
		return len(b), nil
	}
	if w.code == 0 {
		w.code = http.StatusOK
	}
	if len(b) > agentOutputCap-w.buf.Len() {
		w.withhold()
		return len(b), nil
	}
	w.buf.Write(b)
	if w.sse() {
		w.events()
	}
	return len(b), nil
}
func (w *agentWriter) sse() bool {
	return strings.HasPrefix(w.header.Get("Content-Type"), "text/event-stream")
}

// clean checks headers jointly with the payload in both orders. A filename/header
// plus body split must not become two separately approved pieces.
func (w *agentWriter) clean(b []byte) ([]byte, bool) {
	payload := b
	if w.sse() {
		var data []string
		for _, line := range strings.Split(string(b), "\n") {
			if strings.HasPrefix(line, "data:") {
				data = append(data, strings.TrimSpace(strings.TrimPrefix(line, "data:")))
			}
		}
		payload = []byte(strings.Join(data, "\n"))
	}
	scrub := func(b []byte) ([]byte, bool) { return w.s.agentScrub(b, w.actor) }
	if w.catalogResponse(payload) {
		scrub = func(b []byte) ([]byte, bool) {
			clean, bad := w.s.agentCatalogScrub(b)
			if bad || w.s.browser == nil {
				return clean, bad
			}
			return w.s.browser.ScrubOutput(clean, w.actor)
		}
	}
	check := func(body string) bool {
		joint, err := json.Marshal(map[string]any{"headers": w.header, "body": body})
		if err != nil {
			return false
		}
		_, bad := scrub(joint)
		return !bad
	}
	if w.sse() {
		var data []string
		for _, line := range strings.Split(string(b), "\n") {
			if strings.HasPrefix(line, "data:") {
				data = append(data, strings.TrimPrefix(strings.TrimSuffix(line, "\r"), "data:"))
			}
		}
		if !check(strings.Join(data, "\n")) {
			return nil, false
		}
	}
	if !check(string(b)) {
		return nil, false
	}
	out, bad := scrub(b)
	if bad {
		return nil, false
	}
	return out, true
}
func (w *agentWriter) start() {
	if w.started {
		return
	}
	w.started = true
	for k := range w.dst.Header() {
		w.dst.Header().Del(k)
	}
	for k, vals := range w.header {
		key, bad := w.s.agentScrub([]byte(k), w.actor)
		if bad || string(key) != k {
			continue
		}
		for _, v := range vals {
			clean, bad := w.s.agentScrub([]byte(v), w.actor)
			if !bad {
				w.dst.Header().Add(k, string(clean))
			}
		}
	}
	// Rewritten output has a different length; let net/http frame it.
	w.dst.Header().Del("Content-Length")
	if w.code == 0 {
		w.code = http.StatusOK
	}
	w.dst.WriteHeader(w.code)
}
func (w *agentWriter) withhold() {
	if w.stopped {
		return
	}
	w.stopped = true
	w.buf.Reset()
	if w.sse() {
		w.header = http.Header{"Content-Type": {"text/event-stream"}, "Cache-Control": {"no-store"}}
		w.start()
		_, _ = w.dst.Write([]byte("event: error\ndata: {\"error\":\"response withheld\"}\n\n"))
	} else {
		// Discard all variable headers as they may carry the withheld content.
		w.header = http.Header{"Content-Type": {"application/json"}, "Cache-Control": {"no-store"}, "X-RalX-Withheld": {"credential-or-scan-limit"}}
		w.start()
		_, _ = w.dst.Write([]byte(`{"status":"withheld","error":"response withheld - credential or scan limit"}`))
	}
	if f, ok := w.dst.(http.Flusher); ok {
		f.Flush()
	}
}
func (w *agentWriter) events() {
	for !w.stopped {
		b := w.buf.Bytes()
		i, size := bytes.Index(b, []byte("\n\n")), 2
		if cr := bytes.Index(b, []byte("\r\n\r\n")); cr >= 0 && (i < 0 || cr < i) {
			i, size = cr, 4
		}
		if i < 0 {
			return
		}
		frame := append([]byte(nil), w.buf.Next(i+size)...)
		clean, ok := w.clean(frame)
		if !ok {
			w.withhold()
			return
		}
		w.start()
		_, _ = w.dst.Write(clean)
	}
}
func (w *agentWriter) Flush() {
	if w.sse() {
		w.events()
		// Do not flush an incomplete event or its headers before checking it.
		if w.buf.Len() == 0 && !w.stopped {
			if _, ok := w.clean(nil); !ok {
				w.withhold()
				return
			}
			w.start()
		}
		if w.started {
			if f, ok := w.dst.(http.Flusher); ok {
				f.Flush()
			}
		}
	}
}
func (w *agentWriter) finish() {
	if w.stopped {
		return
	}
	if w.sse() {
		w.events()
		if w.buf.Len() != 0 {
			w.withhold()
		} else {
			w.Flush()
		}
		return
	}
	clean, ok := w.clean(w.buf.Bytes())
	if !ok {
		w.withhold()
		return
	}
	w.start()
	_, _ = w.dst.Write(clean)
}

// ResponseController sees only the bounded writer's flush implementation.
func (w *agentWriter) EnableFullDuplex() error {
	return errors.New("full duplex is not supported")
}
