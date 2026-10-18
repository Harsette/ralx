package main

import (
	"context"
	"errors"
	"flag"
	"os"
	"os/exec"
	"path/filepath"
)

// cmdDeploy uses the checked-out deployment script, never downloaded shell code.
func cmdDeploy(ctx context.Context, args []string) error {
	if len(args) == 0 || args[0] != "cloudflare" {
		return errors.New("usage: ralx deploy cloudflare [--source /path/to/ralx] [--local] [--check] [--update]")
	}
	fs := flag.NewFlagSet("deploy cloudflare", flag.ContinueOnError)
	source := fs.String("source", ".", "RalX source checkout")
	local := fs.Bool("local", false, "run only local Wrangler and D1")
	check := fs.Bool("check", false, "stop after local smoke checks")
	update := fs.Bool("update", false, "update an existing self-host deployment")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if len(fs.Args()) != 0 {
		return errors.New("unexpected deployment arguments")
	}
	script, err := filepath.Abs(filepath.Join(*source, "cloud", "scripts", "selfhost.mjs"))
	if err != nil {
		return err
	}
	if _, err := os.Stat(script); err != nil {
		return errors.New("self-host script missing: clone RalX and pass --source /path/to/ralx; run npm ci in cloud first")
	}
	argv := []string{script}
	if *local {
		argv = append(argv, "--local")
	}
	if *check {
		argv = append(argv, "--check")
	}
	if *update {
		argv = append(argv, "--update")
	}
	cmd := exec.CommandContext(ctx, "node", argv...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	return cmd.Run()
}
