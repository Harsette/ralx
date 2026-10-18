package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"github.com/Harsette/ralx/internal/mcpbridge"
	"github.com/Harsette/ralx/internal/setupconfig"
)

type setupDeviceResponse struct {
	DeviceCode           string `json:"device_code"`
	UserCode             string `json:"user_code"`
	VerificationURI      string `json:"verification_uri"`
	VerificationComplete string `json:"verification_uri_complete"`
	Interval             int    `json:"interval"`
	ExpiresIn            int    `json:"expires_in"`
	MachineGrant         string `json:"machine_grant"`
	Error                string `json:"error"`
}

// Never follow redirects with a device secret, grant or client credential.
func setupDevicePost(ctx context.Context, base, path string, value any) (setupDeviceResponse, int, error) {
	var out setupDeviceResponse
	b, err := json.Marshal(value)
	if err != nil {
		return out, 0, err
	}
	req, err := http.NewRequestWithContext(ctx, "POST", base+path, bytes.NewReader(b))
	if err != nil {
		return out, 0, errors.New("invalid RalX origin")
	}
	req.Header.Set("Content-Type", "application/json")
	r, err := setupHTTP().Do(req)
	if err != nil {
		return out, 0, errors.New("RalX could not be reached")
	}
	defer r.Body.Close()
	if err = json.NewDecoder(io.LimitReader(r.Body, 8192)).Decode(&out); err != nil {
		return out, r.StatusCode, errors.New("RalX returned an invalid device response")
	}
	return out, r.StatusCode, nil
}

func setupDeviceAuthorize(ctx context.Context, s setupState, names []string, noBrowser bool) (string, error) {
	machine, err := os.Hostname()
	if err != nil || machine == "" {
		machine = "This computer"
	}
	if len(machine) > 120 {
		machine = machine[:120]
	}
	d, status, err := setupDevicePost(ctx, s.URL, "/device/code", map[string]any{"machine_name": machine, "clients": names})
	if err != nil {
		return "", err
	}
	if status != http.StatusOK {
		return "", errors.New("could not start browser approval; try setup again")
	}
	if !regexp.MustCompile(`^dc_[a-f0-9]{64}$`).MatchString(d.DeviceCode) || !regexp.MustCompile(`^[BCDFGHJKLMNPQRSTVWXYZ23456789]{4}-[BCDFGHJKLMNPQRSTVWXYZ23456789]{4}$`).MatchString(d.UserCode) || d.ExpiresIn < 1 || d.ExpiresIn > 600 || d.Interval < 1 || d.Interval > 60 {
		return "", errors.New("RalX returned an invalid device request")
	}
	expected := s.URL + "/device?user_code=" + d.UserCode
	if d.VerificationURI != s.URL+"/device" || d.VerificationComplete != expected {
		return "", errors.New("RalX returned a verification URL outside its origin")
	}
	fmt.Printf("Connect this computer: %s\nCode: %s\nApprove once in your browser to connect %d agent(s).\n", d.VerificationComplete, d.UserCode, len(names))
	if !noBrowser && os.Getenv("SSH_CONNECTION") == "" && os.Getenv("SSH_TTY") == "" {
		if err := mcpbridge.OpenBrowser(expected); err != nil {
			fmt.Println("Browser could not open. Use the URL and code above on another device.")
		}
	}
	return setupDevicePoll(ctx, s.URL, d)
}

func setupDevicePoll(ctx context.Context, base string, d setupDeviceResponse) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, time.Duration(d.ExpiresIn)*time.Second)
	defer cancel()
	interval := time.Duration(d.Interval) * time.Second
	for {
		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return "", errors.New("browser approval expired or canceled; run setup again")
		case <-timer.C:
		}
		r, status, err := setupDevicePost(ctx, base, "/device/token", map[string]string{"device_code": d.DeviceCode})
		if err != nil {
			if ctx.Err() != nil {
				return "", ctx.Err()
			}
			interval *= 2
			continue
		}
		if status == http.StatusOK {
			if !regexp.MustCompile(`^mg_[a-f0-9]{64}$`).MatchString(r.MachineGrant) {
				return "", errors.New("RalX returned an invalid machine grant")
			}
			return r.MachineGrant, nil
		}
		switch r.Error {
		case "authorization_pending":
		case "slow_down":
			interval += 5 * time.Second
			if time.Duration(r.Interval)*time.Second > interval {
				interval = time.Duration(r.Interval) * time.Second
			}
		case "access_denied":
			return "", errors.New("connection denied in your browser; no client configs changed")
		case "expired_token":
			return "", errors.New("browser approval expired; run setup again")
		default:
			return "", errors.New("browser approval failed; run setup again")
		}
	}
}

func setupDetected(c setupconfig.Client) (bool, string) {
	detected := false
	for _, p := range c.Detect {
		if _, err := os.Stat(p); err == nil {
			detected = true
		}
	}
	cli := ""
	if c.CLI != "" && os.Getenv("RALX_SETUP_SANDBOX") != "1" {
		cli, _ = exec.LookPath(c.CLI)
		detected = detected || cli != ""
	}
	return detected, cli
}
func setupCodeFor(codes []string, name string) string {
	for _, p := range codes {
		if k, v, ok := strings.Cut(p, "="); ok && k == name {
			return v
		}
	}
	return ""
}
func setupDeviceClients(s setupState, selected []string, selection string, codes []string) []string {
	var names []string
	for _, c := range setupClients() {
		if selection == "none" || (selection != "all" && !hasString(selected, c.Name)) || setupCodeFor(codes, c.Name) != "" {
			continue
		}
		if (c.Name == "claude-code" && os.Getenv("CLAUDE_CONFIG_DIR") != "") || (c.Name == "codex" && os.Getenv("CODEX_HOME") != "") {
			continue
		}
		if detected, _ := setupDetected(c); !detected {
			continue
		}
		if _, err := os.Stat(identityFile("setup-" + c.Name)); os.IsNotExist(err) {
			names = append(names, c.Name)
		}
	}
	return names
}

func setupCloudOrigin(value string) (string, error) {
	u, err := url.Parse(value)
	if err != nil || u.Host == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return "", errors.New("--url must be a RalX origin without a path, query or credentials")
	}
	if u.Scheme != "https" && !(os.Getenv("RALX_SETUP_SANDBOX") == "1" && u.Scheme == "http" && u.Hostname() == "127.0.0.1" && u.Port() != "7317") {
		return "", errors.New("cloud URL requires HTTPS")
	}
	return strings.TrimRight(u.String(), "/"), nil
}
