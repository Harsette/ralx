//go:build windows

package client

import (
	"context"
	"net"
	"net/http"
	"time"

	"github.com/Microsoft/go-winio"
)

const DefaultAdminPipe = `\\.\pipe\ralx-admin`

// NewAdmin talks to the daemon over the admin pipe, which only elevated
// administrators (or SYSTEM) can open.
func NewAdmin(pipe string) *Client {
	if pipe == "" {
		pipe = DefaultAdminPipe
	}
	tr := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		timeout := 5 * time.Second
		return winio.DialPipe(pipe, &timeout)
	}}
	return &Client{URL: "http://ralx-admin", HTTP: &http.Client{Transport: tr}, Admin: true}
}
