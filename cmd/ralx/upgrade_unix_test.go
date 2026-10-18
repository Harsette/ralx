//go:build !windows

package main

import "testing"

func TestUpgradeLegacySystemdLayout(t *testing.T) {
	l, e := parseLegacySystemd("[Service]\nUser=ralx\nEnvironment=RALX_DATA=/srv/private/ralx\nExecStart=/opt/ralx/ralx daemon --addr 127.0.0.1:17317 --admin-pipe /run/ralx/private.sock\n")
	if e != nil || l.Binary != "/opt/ralx/ralx" || l.Data != "/srv/private/ralx" || l.Addr != "127.0.0.1:17317" || l.Pipe != "/run/ralx/private.sock" {
		t.Fatalf("layout: %+v (%v)", l, e)
	}
	if _, e = parseLegacySystemd("[Service]\nExecStart=/opt/ralx/ralx unexpected\n"); e == nil {
		t.Fatal("unknown service command accepted")
	}
}
