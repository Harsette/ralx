// Package runner executes real CLIs on RalX's side of the boundary: fixed
// argv (never a shell), a minimal environment built from scratch, secrets
// injected only into the child's environment, a timeout and an output cap.
package runner

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

type Runner struct {
	Tools   map[string]string   // tool name -> absolute binary path (verified)
	Prefix  map[string][]string // fixed leading args, e.g. the script a node binary runs
	HomeDir string            // private home for CLIs (config dirs, temp)
	MaxOut  int64
}

type Result struct {
	ExitCode int    `json:"exit_code"`
	Stdout   string `json:"stdout"`
	Stderr   string `json:"stderr"`
	Truncated bool  `json:"truncated,omitempty"`
}

// capWriter keeps the first n bytes and counts the rest.
type capWriter struct {
	buf       bytes.Buffer
	n         int64
	truncated bool
}

func (w *capWriter) Write(p []byte) (int, error) {
	room := w.n - int64(w.buf.Len())
	if room <= 0 {
		w.truncated = true
		return len(p), nil
	}
	if int64(len(p)) > room {
		w.buf.Write(p[:room])
		w.truncated = true
		return len(p), nil
	}
	return w.buf.Write(p)
}

// Run executes tool with argv and the given extra env (secrets included).
func (r *Runner) Run(ctx context.Context, tool string, argv []string, extraEnv map[string]string, timeout time.Duration, stdin io.Reader) (*Result, error) {
	bin, ok := r.Tools[tool]
	if !ok || bin == "" {
		return nil, fmt.Errorf("tool %q is not installed for RalX", tool)
	}
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, bin, append(append([]string{}, r.Prefix[tool]...), argv...)...)
	cmd.Env = r.baseEnv(tool)
	for k, v := range extraEnv {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	work := filepath.Join(r.HomeDir, "work")
	_ = os.MkdirAll(work, 0o700)
	cmd.Dir = work
	if stdin != nil {
		cmd.Stdin = stdin
	}
	maxOut := r.MaxOut
	if maxOut == 0 {
		maxOut = 1 << 20
	}
	stdout := &capWriter{n: maxOut}
	stderr := &capWriter{n: 64 << 10}
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	prepare(cmd)
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start %s: %w", tool, err)
	}
	cleanup := afterStart(cmd)
	err := cmd.Wait()
	cleanup()
	res := &Result{Stdout: stdout.buf.String(), Stderr: stderr.buf.String(), Truncated: stdout.truncated}
	if ctx.Err() == context.DeadlineExceeded {
		return res, fmt.Errorf("%s timed out after %s", tool, timeout)
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		res.ExitCode = ee.ExitCode()
		return res, nil
	}
	if err != nil {
		return res, err
	}
	return res, nil
}

// baseEnv is built from nothing: the daemon's own environment is never
// inherited, so nothing ambient leaks into or out of a CLI.
func (r *Runner) baseEnv(tool string) []string {
	home := r.HomeDir
	cfg := filepath.Join(home, "config", tool)
	tmp := filepath.Join(home, "tmp")
	_ = os.MkdirAll(cfg, 0o700)
	_ = os.MkdirAll(tmp, 0o700)
	env := []string{
		"HOME=" + home,
		"TMP=" + tmp,
		"TEMP=" + tmp,
		"TMPDIR=" + tmp,
		"NO_COLOR=1",
		"CI=1",
		// gh
		"GH_CONFIG_DIR=" + cfg,
		"GH_PROMPT_DISABLED=1",
		"GH_NO_UPDATE_NOTIFIER=1",
		"GH_SPINNER_DISABLED=1",
		"GH_PAGER=",
		"PAGER=",
		// vercel / supabase / generic XDG
		"XDG_CONFIG_HOME=" + cfg,
		"XDG_DATA_HOME=" + filepath.Join(home, "data"),
		"XDG_CACHE_HOME=" + filepath.Join(home, "cache"),
	}
	if runtime.GOOS == "windows" {
		sysroot := os.Getenv("SystemRoot")
		if sysroot == "" {
			sysroot = `C:\Windows`
		}
		env = append(env,
			"SystemRoot="+sysroot,
			"SYSTEMDRIVE="+filepath.VolumeName(sysroot),
			"windir="+sysroot,
			"ComSpec="+filepath.Join(sysroot, "System32", "cmd.exe"),
			"PATHEXT=.COM;.EXE;.BAT;.CMD",
			"PATH="+strings.Join([]string{filepath.Join(sysroot, "System32"), sysroot, filepath.Dir(r.Tools[tool])}, ";"),
			"USERPROFILE="+home,
			"APPDATA="+filepath.Join(home, "AppData", "Roaming"),
			"LOCALAPPDATA="+filepath.Join(home, "AppData", "Local"),
			"PROGRAMDATA="+filepath.Join(home, "ProgramData"),
		)
	} else {
		env = append(env, "PATH=/usr/bin:/bin:"+filepath.Dir(r.Tools[tool]))
	}
	return env
}
