package daemon

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"github.com/Harsette/ralx/internal/actions"
	"github.com/Harsette/ralx/internal/store"
)

var placeholderRe = regexp.MustCompile(`\{\{([a-z0-9][a-z0-9_.:-]{0,63}?)(?:\.([a-z0-9_]{1,40}))?\}\}`)

// restrictedReqHeaders can't be set by an agent (they'd change routing/identity).
var restrictedReqHeaders = map[string]bool{"host": true, "content-length": true}

// methodOverrideHeaders would turn a GET into a write at an API that honours
// them, slipping past the method enum and the approval gate (Astra N2). They are
// rejected outright, for every method.
var methodOverrideHeaders = map[string]bool{
	"x-http-method-override": true,
	"x-http-method":          true,
	"x-method-override":      true,
}

// httpRequestAction is the generic "call any connected service's API" action.
// The agent writes {{credential}} or {{credential.field}} in a header, the URL
// or the body; RalX substitutes the real secret at send time, but only if the
// target host is on that credential's mandatory allow-list, and redacts the
// response. Every generic request is held; named read actions provide routine reads.
func (s *Server) httpRequestAction() *actions.Action {
	return &actions.Action{
		Name:            "http.request",
		Description:     "Call any connected service's REST API. Put {{name}} or {{name.field}} (a credential in RalX) in a header value, the URL or the body; RalX swaps in the real secret at send time, only if the host is on that credential's allow-list, and redacts the response. Every generic request is held for the owner's approval , a host allow-list grants permission to a host, not to a specific operation, and a GET's path, matrix parameters or encoded query can itself select an effect (Astra A10). For routine reads, use a named read action instead (gh.api.get, gh.repo.view, drive/gmail reads, etc.).",
		Risk:            actions.Write,
		GateReason:      "shares data",
		SummaryTemplate: "{method} {url}",
		// An outbound request is an outward action AND a host allow-list is not
		// operation approval: even an allow-listed GET can carry an effect in its
		// path/matrix/encoded query, and no reliable rule separates a read from a
		// write at this layer (Astra A10 across three rounds). Hold generic
		// http.request unconditionally; routine reads go through named read actions.
		GateFunc: func(a map[string]any) bool { return true },
		Params: []actions.Param{
			{Name: "method", Type: "string", Enum: []string{"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"}, Default: "GET"},
			{Name: "url", Type: "string", Required: true, Pattern: `https://[^\s]{3,1000}`, MaxLen: 2048},
			{Name: "headers", Type: "array", Description: `Headers as "Name: Value"; a value may contain {{credential}}`, AllowLeadingDash: true, MaxLen: 4096},
			{Name: "body", Type: "string", MaxLen: 1 << 20, AllowLeadingDash: true, Description: "Request body; may contain {{credential}}"},
		},
		Native: s.doHTTPRequest,
	}
}

// httpHeaderLines pulls the headers argument out as plain strings, whatever
// concrete slice type it arrived as.
func httpHeaderLines(a map[string]any) []string {
	switch hs := a["headers"].(type) {
	case []string:
		return hs
	case []any:
		out := make([]string, 0, len(hs))
		for _, h := range hs {
			out = append(out, fmt.Sprint(h))
		}
		return out
	}
	return nil
}

// httpHasMethodOverride reports whether any header tries to override the method.
func httpHasMethodOverride(a map[string]any) bool {
	for _, line := range httpHeaderLines(a) {
		if i := strings.IndexByte(line, ':'); i > 0 {
			if methodOverrideHeaders[strings.ToLower(strings.TrimSpace(line[:i]))] {
				return true
			}
		}
	}
	return false
}

// httpHasCredentialRef reports whether the request references a RalX credential
// (so its host allow-list will constrain the destination).
func httpHasCredentialRef(a map[string]any) bool {
	rawURL, _ := a["url"].(string)
	body, _ := a["body"].(string)
	combined := rawURL + "\n" + strings.Join(httpHeaderLines(a), "\n") + "\n" + body
	return placeholderRe.MatchString(combined)
}

// httpHasBody reports whether the request carries a body.
func httpHasBody(a map[string]any) bool {
	b, _ := a["body"].(string)
	return strings.TrimSpace(b) != ""
}

// httpHasQuery reports whether the request URL carries a query string.
func httpHasQuery(a map[string]any) bool {
	raw, _ := a["url"].(string)
	if u, err := url.Parse(raw); err == nil {
		return u.RawQuery != ""
	}
	return false
}

// methodOverrideQueryKeys are query parameters some frameworks honour to override
// the HTTP method (e.g. ?_method=DELETE). They turn a read into a write.
var methodOverrideQueryKeys = map[string]bool{"_method": true, "x-http-method-override": true, "x-http-method": true}

// httpHasMethodOverrideQuery reports whether the URL carries a method-override
// query parameter.
func httpHasMethodOverrideQuery(a map[string]any) bool {
	raw, _ := a["url"].(string)
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	for k := range u.Query() {
		if methodOverrideQueryKeys[strings.ToLower(k)] {
			return true
		}
	}
	return false
}

func hostAllowed(host string, allowed []string) bool {
	host = strings.ToLower(host)
	for _, e := range allowed {
		e = strings.ToLower(strings.TrimSpace(e))
		if e == "" {
			continue
		}
		// A plain entry matches that exact host only; subdomains are allowed only
		// by an explicit "*." wildcard, so "api.github.com" can't also authorise
		// "x.api.github.com" (Daru review).
		if strings.HasPrefix(e, "*.") {
			base := e[2:]
			if host == base || strings.HasSuffix(host, "."+base) {
				return true
			}
			continue
		}
		if host == e {
			return true
		}
	}
	return false
}

func (s *Server) doHTTPRequest(ctx context.Context, env actions.Env, args map[string]any) (any, error) {
	method := strings.ToUpper(fmt.Sprint(args["method"]))
	if method == "" {
		method = "GET"
	}
	rawURL, _ := args["url"].(string)
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return nil, errors.New("url must be an absolute https URL")
	}
	for k := range u.Query() {
		if methodOverrideQueryKeys[strings.ToLower(k)] {
			return nil, fmt.Errorf("query parameter %q is not allowed (it would change the request method)", k)
		}
	}
	host := u.Hostname()

	headerLines := httpHeaderLines(args)
	body, _ := args["body"].(string)

	// Find every credential placeholder across the URL, headers and body, and
	// enforce each one's host allow-list before substituting anything.
	combined := rawURL + "\n" + strings.Join(headerLines, "\n") + "\n" + body
	refs := map[string]bool{}
	for _, m := range placeholderRe.FindAllStringSubmatch(combined, -1) {
		refs[m[1]] = true
	}
	secretVals := map[string]string{} // "name" or "name.field" -> value
	for name := range refs {
		// One immutable snapshot: authorize on the allow-list and substitute the
		// value from the SAME row read, so a concurrent credential replacement can't
		// let us check version A's allowed_hosts and then send version B's key (Daru6
		// run6: host authorization and secret retrieval must use one version).
		cred, fields, err := s.store.BoundSecret(ctx, name)
		if err != nil {
			return nil, fmt.Errorf("unknown credential %q", name)
		}
		allowed := credAllowedHosts(cred.Meta)
		if len(allowed) == 0 {
			return nil, fmt.Errorf("credential %q has no allowed_hosts set; an owner must set them before it can be used in http.request", name)
		}
		if !hostAllowed(host, allowed) {
			return nil, fmt.Errorf("credential %q is not allowed to be sent to %s (allowed: %s)", name, host, strings.Join(allowed, ", "))
		}
		for k, v := range fields {
			if store.SecretField(cred.Kind, k) {
				s.red.Add(name+":"+k, v)
			}
			secretVals[name+"."+k] = v
		}
		if d := defaultField(fields); d != "" {
			secretVals[name] = fields[d]
		}
	}

	subst := func(in string) (string, error) {
		var subErr error
		out := placeholderRe.ReplaceAllStringFunc(in, func(ph string) string {
			m := placeholderRe.FindStringSubmatch(ph)
			key := m[1]
			if m[2] != "" {
				key = m[1] + "." + m[2]
			}
			v, ok := secretVals[key]
			if !ok {
				subErr = fmt.Errorf("unknown placeholder %s", ph)
				return ph
			}
			return v
		})
		return out, subErr
	}

	finalURL, err := subst(rawURL)
	if err != nil {
		return nil, err
	}
	// The host must not change after substitution (a placeholder can't be used
	// to redirect the credential to another host).
	if fu, err := url.Parse(finalURL); err != nil || !strings.EqualFold(fu.Hostname(), host) {
		return nil, errors.New("the URL host may not come from a placeholder")
	}
	finalBody, err := subst(body)
	if err != nil {
		return nil, err
	}

	var reqBody io.Reader
	if finalBody != "" {
		reqBody = strings.NewReader(finalBody)
	}
	req, err := http.NewRequestWithContext(ctx, method, finalURL, reqBody)
	if err != nil {
		return nil, err
	}
	for _, line := range headerLines {
		i := strings.IndexByte(line, ':')
		if i <= 0 {
			return nil, fmt.Errorf("bad header %q (use \"Name: Value\")", line)
		}
		name := strings.TrimSpace(line[:i])
		if methodOverrideHeaders[strings.ToLower(name)] {
			return nil, fmt.Errorf("header %q is not allowed (it would change the request method)", name)
		}
		if restrictedReqHeaders[strings.ToLower(name)] {
			continue
		}
		val, err := subst(strings.TrimSpace(line[i+1:]))
		if err != nil {
			return nil, err
		}
		req.Header.Set(name, val)
	}
	if req.Header.Get("Accept") == "" {
		req.Header.Set("Accept", "application/json, */*")
	}

	client := s.ext
	if client == nil {
		client = safeHTTPClient()
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, errors.New(s.red.String(err.Error()))
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	respBody := string(data)
	// A secret can be split across two header values, or between a header and the
	// body, so no single value contains it. Deep-scan the concatenation of every
	// returned header value AND the body together; if that reconstructs a
	// credential, withhold the whole response , headers and body (Astra5 split
	// headers). Otherwise scan each value on its own as before.
	var rawVals []string
	for k, v := range resp.Header {
		lk := strings.ToLower(k)
		if lk == "set-cookie" || lk == "authorization" {
			continue
		}
		// Collect each value element individually (a header can repeat), not just the
		// ", "-joined form, so a secret split across duplicate header values is caught
		// when the agent concatenates them with no separator (Astra6 run6 duplicate
		// encoded header).
		rawVals = append(rawVals, v...)
	}
	// Scan the literal join, and the header values (and header-values+body) joined
	// with no separator in sorted order AND reversed, so a secret split across two
	// headers , or a header and the body , is caught whichever order the agent
	// reassembles it, independent of Go's random header map order (Astra5/Astra6).
	headersAndBody := append(append([]string(nil), rawVals...), respBody)
	if s.red.DeepContainsSecret(strings.Join(rawVals, "\n")+"\n"+respBody) ||
		s.anyOrderingLeaks(rawVals) || s.anyOrderingLeaks(headersAndBody) {
		return map[string]any{
			"status":  resp.StatusCode,
			"headers": map[string]string{"X-RalX-Withheld": "credential"},
			"body":    "[REDACTED: response withheld , it reconstructs a credential]",
		}, nil
	}
	outHeaders := map[string]string{}
	for k, v := range resp.Header {
		lk := strings.ToLower(k)
		if lk == "set-cookie" || lk == "authorization" {
			continue
		}
		val := strings.Join(v, ", ")
		if s.red.DeepContainsSecret(val) {
			val = "[REDACTED]"
		}
		outHeaders[k] = s.red.String(val)
	}
	respBody = s.red.String(respBody)
	return map[string]any{
		"status":  resp.StatusCode,
		"headers": outHeaders,
		"body":    respBody,
	}, nil
}

// anyOrderingLeaks reports whether the parts, joined with no separator in sorted
// order or its reverse, deep-contain a secret. This catches a credential split
// across two values whichever order the agent reassembles them; an arbitrary
// N-way permutation split remains a documented residual (Astra5).
func (s *Server) anyOrderingLeaks(parts []string) bool {
	if len(parts) < 2 {
		return false
	}
	sorted := append([]string(nil), parts...)
	sort.Strings(sorted)
	if s.red.DeepContainsSecret(strings.Join(sorted, "")) {
		return true
	}
	rev := make([]string, len(sorted))
	for i, p := range sorted {
		rev[len(sorted)-1-i] = p
	}
	return s.red.DeepContainsSecret(strings.Join(rev, ""))
}

func credAllowedHosts(meta map[string]any) []string {
	switch v := meta["allowed_hosts"].(type) {
	case []any:
		var out []string
		for _, x := range v {
			if s, ok := x.(string); ok && s != "" {
				out = append(out, s)
			}
		}
		return out
	case []string:
		return v
	case string:
		var out []string
		for _, s := range strings.Split(v, ",") {
			if s = strings.TrimSpace(s); s != "" {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

// defaultField picks the single secret field to use for a bare {{name}}.
func defaultField(fields map[string]string) string {
	for _, pref := range []string{"token", "api_key", "key", "secret"} {
		if _, ok := fields[pref]; ok {
			return pref
		}
	}
	if len(fields) == 1 {
		for k := range fields {
			return k
		}
	}
	return ""
}
