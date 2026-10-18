package browserlogin

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/chromedp/cdproto/fetch"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"
)

const passwordURLReason = "the page tried to put the password in a web address"

// Each target keeps its own interceptor. Retaining it after a fill also protects
// delayed handlers and avoids releasing paused requests by disabling Fetch.
// The next password replaces the old value; closing the session stops the loop.
type passwordGuard struct {
	mu              sync.Mutex
	password        string
	blocked, broken bool
}

func passwordInURL(raw, password string) bool {
	if password == "" {
		return false
	}
	// Check both path escaping and HTML form escaping, including nested escaping.
	for _, form := range []bool{false, true} {
		value := raw
		for i := 0; i < 4; i++ {
			if strings.Contains(value, password) {
				return true
			}
			next := decodeURLValue(value, form)
			if next == value {
				break
			}
			value = next
		}
	}
	return false
}

// A malformed escape elsewhere in the URL must not hide valid escapes around
// the password. Preserve malformed bytes while decoding every valid triplet.
func decodeURLValue(raw string, form bool) string {
	hex := func(c byte) int {
		switch {
		case c >= '0' && c <= '9':
			return int(c - '0')
		case c >= 'a' && c <= 'f':
			return int(c-'a') + 10
		case c >= 'A' && c <= 'F':
			return int(c-'A') + 10
		}
		return -1
	}
	var b strings.Builder
	for i := 0; i < len(raw); i++ {
		if raw[i] == '%' && i+2 < len(raw) {
			a, z := hex(raw[i+1]), hex(raw[i+2])
			if a >= 0 && z >= 0 {
				b.WriteByte(byte(a*16 + z))
				i += 2
				continue
			}
		}
		if form && raw[i] == '+' {
			b.WriteByte(' ')
		} else {
			b.WriteByte(raw[i])
		}
	}
	return b.String()
}

func (s *Session) guardPassword(password string) error {
	if s.passwordGuard != nil {
		s.passwordGuard.mu.Lock()
		s.passwordGuard.password = password
		s.passwordGuard.blocked = false
		s.passwordGuard.mu.Unlock()
		return s.passwordGuard.reason()
	}
	g := &passwordGuard{password: password}
	s.passwordGuard = g
	events := chromedp.Events(s.ctx, fetch.RequestPaused)
	go func() {
		for event, err := range events {
			if err != nil {
				g.mu.Lock()
				g.broken = true
				g.mu.Unlock()
				return
			}
			g.mu.Lock()
			blocked := event.Request == nil || passwordInURL(event.Request.URL, g.password)
			g.blocked = g.blocked || blocked
			g.mu.Unlock()
			ctx, cancel := context.WithTimeout(s.ctx, 5*time.Second)
			if blocked {
				_, err = chromedp.Call(ctx, fetch.FailRequest, fetch.FailRequestParams{RequestID: event.RequestID, ErrorReason: network.ErrorReasonBlockedByClient})
			} else {
				_, err = chromedp.Call(ctx, fetch.ContinueRequest, fetch.ContinueRequestParams{RequestID: event.RequestID})
			}
			cancel()
			if err != nil {
				g.mu.Lock()
				g.broken = true
				g.mu.Unlock()
				return
			}
		}
	}()
	ctx, cancel := context.WithTimeout(s.ctx, 5*time.Second)
	defer cancel()
	_, err := chromedp.Call(ctx, fetch.Enable, fetch.EnableParams{Patterns: []*fetch.RequestPattern{{URLPattern: "*", RequestStage: fetch.RequestStageRequest}}})
	if err != nil {
		g.mu.Lock()
		g.broken = true
		g.mu.Unlock()
		return errors.New("cannot protect password requests")
	}
	return nil
}

func (g *passwordGuard) reason() error {
	if g == nil {
		return nil
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.blocked {
		return errors.New(passwordURLReason)
	}
	if g.broken {
		return errors.New("password request protection failed")
	}
	return nil
}
