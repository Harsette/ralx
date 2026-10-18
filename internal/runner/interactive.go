package runner

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Session is a long-running CLI process (a login flow) whose output RalX
// watches for a URL to show the user, and whose stdin RalX can write to.
type Session struct {
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	mu     sync.Mutex
	output strings.Builder
	url    string
	done   chan struct{}
	err    error
	stop   func()
}

// StartLogin runs tool argv in the tool's private config home and returns
// once a URL matching urlRe has been printed (or the process ends).
func (r *Runner) StartLogin(tool string, argv []string, extraEnv map[string]string, urlRe *regexp.Regexp, timeout time.Duration) (*Session, error) {
	bin, ok := r.Tools[tool]
	if !ok {
		return nil, fmt.Errorf("tool %q is not installed for RalX", tool)
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	cmd := exec.CommandContext(ctx, bin, append(append([]string{}, r.Prefix[tool]...), argv...)...)
	cmd.Env = r.baseEnv(tool)
	for k, v := range extraEnv {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	work := filepath.Join(r.HomeDir, "work")
	_ = os.MkdirAll(work, 0o700)
	cmd.Dir = work
	stdin, err := cmd.StdinPipe()
	if err != nil {
		cancel()
		return nil, err
	}
	pr, pw := io.Pipe()
	cmd.Stdout, cmd.Stderr = pw, pw
	prepare(cmd)
	if err := cmd.Start(); err != nil {
		cancel()
		return nil, err
	}
	cleanup := afterStart(cmd)
	s := &Session{cmd: cmd, stdin: stdin, done: make(chan struct{}), stop: func() { cancel(); cleanup() }}
	found := make(chan struct{}, 1)
	go func() {
		sc := bufio.NewScanner(pr)
		sc.Buffer(make([]byte, 64<<10), 1<<20)
		for sc.Scan() {
			line := sc.Text()
			s.mu.Lock()
			if s.output.Len() < 64<<10 {
				s.output.WriteString(line + "\n")
			}
			if s.url == "" {
				if m := urlRe.FindString(line); m != "" {
					s.url = m
					found <- struct{}{}
				}
			}
			s.mu.Unlock()
		}
	}()
	go func() {
		s.err = cmd.Wait()
		pw.Close()
		cleanup()
		cancel()
		close(s.done)
	}()
	select {
	case <-found:
	case <-s.done:
	case <-time.After(30 * time.Second):
	}
	return s, nil
}

func (s *Session) URL() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.url
}

// Output is everything the CLI printed (callers must redact before showing).
func (s *Session) Output() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.output.String()
}

func (s *Session) Write(input string) error {
	_, err := io.WriteString(s.stdin, input)
	return err
}

// Done reports whether the process has exited, and its error.
func (s *Session) Done() (bool, error) {
	select {
	case <-s.done:
		return true, s.err
	default:
		return false, nil
	}
}

func (s *Session) Wait(d time.Duration) (bool, error) {
	select {
	case <-s.done:
		return true, s.err
	case <-time.After(d):
		return false, nil
	}
}

func (s *Session) Stop() { s.stop() }

// ConfigDir is where a tool keeps its own config inside RalX's private home.
func (r *Runner) ConfigDir(tool string) string { return filepath.Join(r.HomeDir, "config", tool) }

// Home is the private home directory given to every CLI.
func (r *Runner) Home() string { return r.HomeDir }
