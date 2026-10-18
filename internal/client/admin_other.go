//go:build !windows

package client

import (
	"context"
	"net"
	"net/http"
)

const DefaultAdminPipe = "/run/ralx/admin.sock"

func NewAdmin(sock string) *Client {
	if sock == "" {
		sock = DefaultAdminPipe
	}
	tr := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "unix", sock)
	}}
	return &Client{URL: "http://ralx-admin", HTTP: &http.Client{Transport: tr}, Admin: true}
}
