package loginorigin

import (
	"errors"
	"net"
	"net/url"
	"strconv"
	"strings"
)

var ErrInvalid = errors.New("invalid website origin")

// Normalize validates syntax only. It never inspects credential values.
func Normalize(raw string) (string, error) {
	u, e := url.Parse(raw)
	if e != nil || u.User != nil || u.Host == "" || u.Opaque != "" || (u.Scheme != "http" && u.Scheme != "https") || strings.ContainsAny(u.Host, "%\\\r\n\t ") || u.Hostname() == "" {
		return "", ErrInvalid
	}
	if strings.HasSuffix(u.Host, ":") {
		return "", ErrInvalid
	}
	hostname := u.Hostname()
	if strings.Contains(hostname, ":") {
		if net.ParseIP(hostname) == nil {
			return "", ErrInvalid
		}
	} else {
		for _, r := range hostname {
			if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '.') {
				return "", ErrInvalid
			}
		}
		if len(hostname) > 253 {
			return "", ErrInvalid
		}
		for _, label := range strings.Split(strings.TrimSuffix(hostname, "."), ".") {
			if label == "" || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
				return "", ErrInvalid
			}
		}
	}
	if p := u.Port(); p != "" {
		n, e := strconv.Atoi(p)
		if e != nil || n < 1 || n > 65535 {
			return "", ErrInvalid
		}
	}
	host := strings.ToLower(u.Host)
	if (u.Scheme == "http" && u.Port() == "80") || (u.Scheme == "https" && u.Port() == "443") {
		host = strings.ToLower(u.Hostname())
		if strings.Contains(host, ":") {
			host = "[" + host + "]"
		}
	}
	return u.Scheme + "://" + host, nil
}

func Exact(raw string) (string, error) {
	u, e := url.Parse(raw)
	if e != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return "", ErrInvalid
	}
	return Normalize(raw)
}
