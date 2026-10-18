package daemon

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// HubConfig is read from <data>/config.yaml (admin-only folder). It decides
// how the hub is reached from outside: the same binary works behind a VPS
// reverse proxy, a tunnel, or `tailscale serve`; only this file changes.
type HubConfig struct {
	// PublicOrigins are trusted HTTPS origins the hub is served on besides
	// localhost: a tailnet name (tailscale serve) or a LAN name. Full admin is
	// allowed here. TLS is terminated by the proxy/tunnel in front of the hub.
	PublicOrigins []string `yaml:"public_origins"`
	// InternetOrigins are HTTPS origins reachable from the open internet (a VPS
	// domain or a Tailscale Funnel/Cloudflare tunnel name). They serve only
	// OAuth, /mcp, the agent REST API and approve/deny; credential reveal,
	// agent management, connections, paste links and setup are refused here and
	// only work on the local pipe or a tailnet/LAN origin (Daru's split).
	InternetOrigins []string `yaml:"internet_origins"`
	// NotifyWebhook receives a JSON POST for every held action, so a bot can
	// ping the owner's phone with the approval link.
	NotifyWebhook string `yaml:"notify_webhook"`
	// GoogleWebClient: when the hub is remote, Google needs a Web OAuth client
	// whose redirect is <public origin>/oauth/google/callback. Stored in the
	// vault as "google-oauth-web-client"; this flag picks it.
	GoogleRedirectOrigin string `yaml:"google_redirect_origin"`
	// PrivateListen adds listeners on private-network addresses (a Tailscale
	// 100.x IP or a LAN IP) for agents on that network, over plain HTTP
	// inside the network's own encryption. Public addresses are refused:
	// going public always goes through a TLS proxy or tunnel.
	PrivateListen []string `yaml:"private_listen"`
	// PrivateHosts are extra Host headers accepted on those listeners, e.g.
	// "workstation:7317" or "workstation.example.invalid:7317".
	PrivateHosts []string `yaml:"private_hosts"`
	// TrustedProxy declares that a reverse proxy sits in front of the hub for its
	// public/internet origin(s). When set, sensitive admin is refused on any
	// request that resolves to a loopback origin (it can't be proven to be genuine
	// local admin rather than a public request the proxy relayed with a rewritten
	// Host and a missing or non-local X-Forwarded-Host) , administer over the admin
	// pipe or a tailnet/LAN origin instead (Astra A13). Leave it false for a
	// local-only or tailnet-only deployment.
	TrustedProxy bool `yaml:"trusted_proxy"`
}

func isPrivateListen(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	return ip.IsLoopback() || ip.IsPrivate() || isCGNAT(ip)
}

func loadHubConfig(dataDir string) (HubConfig, error) {
	var c HubConfig
	b, err := os.ReadFile(filepath.Join(dataDir, "config.yaml"))
	if os.IsNotExist(err) {
		return c, nil
	}
	if err != nil {
		return c, err
	}
	if err := yaml.Unmarshal(b, &c); err != nil {
		return c, fmt.Errorf("config.yaml: %w", err)
	}
	if env := os.Getenv("RALX_PUBLIC_ORIGINS"); env != "" {
		c.PublicOrigins = append(c.PublicOrigins, strings.Split(env, ",")...)
	}
	if env := os.Getenv("RALX_INTERNET_ORIGINS"); env != "" {
		c.InternetOrigins = append(c.InternetOrigins, strings.Split(env, ",")...)
	}
	cleanOrigins := func(list []string) ([]string, error) {
		var out []string
		for _, o := range list {
			o = strings.TrimRight(strings.TrimSpace(o), "/")
			u, err := url.Parse(o)
			if err != nil || u.Scheme != "https" || u.Host == "" || u.Path != "" {
				return nil, fmt.Errorf("origin %q must look like https://host[:port]", o)
			}
			out = append(out, o)
		}
		return out, nil
	}
	if c.PublicOrigins, err = cleanOrigins(c.PublicOrigins); err != nil {
		return c, err
	}
	if c.InternetOrigins, err = cleanOrigins(c.InternetOrigins); err != nil {
		return c, err
	}
	for _, l := range c.PrivateListen {
		if !isPrivateListen(l) {
			return c, fmt.Errorf("private_listen %q must be a private, Tailscale (100.64/10) or loopback IP:port", l)
		}
		c.PrivateHosts = append(c.PrivateHosts, l)
	}
	for i, h := range c.PrivateHosts {
		c.PrivateHosts[i] = strings.ToLower(strings.TrimSpace(h))
	}
	return c, nil
}

// originFor returns the external origin a request came in on: one of the
// configured HTTPS origins, or http://localhost:<port> for local use.
func (s *Server) originFor(r *http.Request) string {
	host := strings.ToLower(r.Host)
	for _, o := range append(append([]string{}, s.hub.PublicOrigins...), s.hub.InternetOrigins...) {
		if u, _ := url.Parse(o); u != nil && strings.ToLower(u.Host) == host {
			return o
		}
	}
	if strings.HasPrefix(host, "127.0.0.1:") || strings.HasPrefix(host, "[::1]:") {
		return "http://" + host
	}
	for _, h := range s.hub.PrivateHosts {
		if h == host {
			return "http://" + host
		}
	}
	return s.origin
}

// remoteIsPublic reports whether the request's immediate peer is a public
// internet address. Locality must not be decided by the Host header alone: a
// remote peer can send Host: localhost (Astra N11). A real proxy/tunnel for the
// public URL rewrites Host to the configured internet origin (refused by
// isInternetOrigin), and tailnet/LAN peers have private addresses, so a
// local-looking origin reached from a public peer is a spoof. An unparseable or
// pipe peer (tests, local socket) is treated as local.
func remoteIsPublic(r *http.Request) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	return !(ip.IsLoopback() || ip.IsPrivate() || isCGNAT(ip) || ip.IsLinkLocalUnicast())
}

// funneled reports whether a request came in over Tailscale Funnel (public
// internet). Tailscale sets this header on funneled requests; behind Serve the
// peer address is loopback, so this header is the only signal that a tailnet
// hostname is actually internet-reachable. Sensitive/local-only routes treat it
// as public (Daru review).
func funneled(r *http.Request) bool {
	return r.Header.Get("Tailscale-Funnel-Request") != ""
}

// forwardedHost returns the client-facing host from X-Forwarded-Host. A chain of
// proxies sends a comma-separated list (original-client, proxy1, …); the first
// entry is the original client's host. Comparing the whole raw string (as before)
// missed a chain and an absent header entirely (Astra A13).
func forwardedHost(r *http.Request) string {
	xf := r.Header.Get("X-Forwarded-Host")
	if i := strings.IndexByte(xf, ','); i >= 0 {
		xf = xf[:i]
	}
	return strings.ToLower(strings.TrimSpace(xf))
}

// isLoopbackHostPort reports whether a Host header names the loopback interface.
func isLoopbackHostPort(host string) bool {
	host = strings.ToLower(host)
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	return host == "localhost" || host == "127.0.0.1" || host == "::1" || host == "[::1]"
}

// isKnownLocalHost reports whether h is one of the hub's own trusted non-internet
// Host values (loopback, a configured tailnet/LAN public origin, or a private
// listener host).
func (s *Server) isKnownLocalHost(h string) bool {
	h = strings.ToLower(strings.TrimSpace(h))
	if isLoopbackHostPort(h) {
		return true
	}
	for _, o := range s.hub.PublicOrigins {
		if u, _ := url.Parse(o); u != nil && strings.EqualFold(u.Host, h) {
			return true
		}
	}
	for _, ph := range s.hub.PrivateHosts {
		if ph == h {
			return true
		}
	}
	return false
}

// isInternetOrigin reports whether a request arrived on an internet-facing
// origin, where sensitive admin is refused (item b of Daru's split).
func (s *Server) isInternetOrigin(r *http.Request) bool {
	o := s.originFor(r)
	for _, io := range s.hub.InternetOrigins {
		if io == o {
			return true
		}
	}
	// A local reverse proxy may forward with a localhost Host but name the real
	// public host in X-Forwarded-Host (possibly a comma chain). If its first entry
	// names an internet origin, treat the request as internet-facing (fail-closed ,
	// this only adds restriction, Astra R14/A13).
	xf := forwardedHost(r)
	if xf != "" {
		for _, io := range s.hub.InternetOrigins {
			if u, _ := url.Parse(io); u != nil && strings.EqualFold(u.Host, xf) {
				return true
			}
		}
	}
	// Behind a declared reverse proxy, a request that resolves to a loopback origin
	// can't be proven to be genuine local admin rather than a public request the
	// proxy relayed with a rewritten Host and a missing/non-local X-Forwarded-Host.
	// Fail closed: treat loopback-resolving and relayed-outside-host requests as
	// internet-facing; the owner administers over the pipe or a tailnet/LAN origin
	// (Astra A13).
	if s.hub.TrustedProxy {
		if isLoopbackHostPort(r.Host) {
			return true
		}
		if xf != "" && !s.isKnownLocalHost(xf) {
			return true
		}
	}
	return false
}

// rpFor is the passkey relying-party id (hostname) for a request.
func (s *Server) rpFor(r *http.Request) string { return rpIDOf(s.originFor(r)) }

// allowedBrowserOrigin reports whether an Origin header is one RalX serves
// (so a legitimate browser MCP client, e.g. the Inspector on loopback, works)
// rather than an arbitrary website.
func (s *Server) allowedBrowserOrigin(o string) bool {
	u, err := url.Parse(o)
	if err != nil {
		return false
	}
	h := u.Hostname()
	if h == "localhost" || h == "127.0.0.1" || h == "::1" {
		return true
	}
	for _, allowed := range append(append([]string{s.origin}, s.hub.PublicOrigins...), s.hub.InternetOrigins...) {
		if sameOriginStr(allowed, o) {
			return true
		}
	}
	return false
}

func sameOriginStr(a, b string) bool {
	ua, ea := url.Parse(a)
	ub, eb := url.Parse(b)
	return ea == nil && eb == nil && strings.EqualFold(ua.Scheme, ub.Scheme) && strings.EqualFold(ua.Host, ub.Host)
}

// publicHosts lists the Host headers the hub accepts besides loopback.
func (s *Server) publicHosts() []string {
	var out []string
	for _, o := range append(append([]string{}, s.hub.PublicOrigins...), s.hub.InternetOrigins...) {
		if u, _ := url.Parse(o); u != nil {
			out = append(out, strings.ToLower(u.Host))
		}
	}
	return append(out, s.hub.PrivateHosts...)
}

// allOrigins is every origin the hub serves, for passkey relying parties.
func (s *Server) allOrigins() []string {
	return append(append([]string{s.origin}, s.hub.PublicOrigins...), s.hub.InternetOrigins...)
}
