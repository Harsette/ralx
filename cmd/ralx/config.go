package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/pelletier/go-toml/v2"
)

func doctorClientHint(name string, installed bool) string {
	if !installed {
		return "- " + name + " not installed"
	}
	return "- " + name + " not connected; fix: ralx setup --clients " + name
}

// cmdConfig prints examples only. Each app still needs its own enrolled identity.
func cmdConfig(args []string) error {
	if len(args) != 1 {
		return errors.New("usage: ralx config <app> (or ralx config --list)")
	}
	if args[0] == "--list" {
		for _, c := range setupClients() {
			fmt.Println(c.Name)
		}
		fmt.Println("stdio\nhttp")
		return nil
	}
	s, e := readSetup()
	if e != nil && !os.IsNotExist(e) {
		return e
	}
	if s.Exe == "" {
		s.Exe, e = os.Executable()
		if e != nil {
			return e
		}
	}
	if s.URL == "" {
		s.URL = "http://127.0.0.1:7317"
	}
	if args[0] == "http" {
		printJSON(map[string]any{"servers": map[string]any{"ralx": map[string]any{"type": "http", "url": s.URL + "/mcp", "headers": map[string]string{"Authorization": "Bearer <this client's RalX agent key>"}}}})
		return nil
	}
	for _, c := range setupClients() {
		if c.Name != args[0] {
			continue
		}
		server := setupServer(s, c.Name)
		server.Env["RALX_AGENT_KEY_FILE"] = "<your enrolled identity file>"
		if c.Format == "toml" {
			encoded, _ := json.Marshal(server)
			var entry map[string]any
			if err := json.Unmarshal(encoded, &entry); err != nil {
				return err
			}
			b, err := toml.Marshal(map[string]any{c.Group: map[string]any{"ralx": entry}})
			if err != nil {
				return err
			}
			fmt.Print(string(b))
		} else {
			printJSON(map[string]any{c.Group: map[string]any{"ralx": server}})
		}
		return nil
	}
	if args[0] == "stdio" {
		server := setupServer(s, "other")
		server.Env["RALX_AGENT_KEY_FILE"] = "<your enrolled identity file>"
		printJSON(map[string]any{"mcpServers": map[string]any{"ralx": server}})
		return nil
	}
	return fmt.Errorf("unknown app %q; run ralx config --list", args[0])
}
