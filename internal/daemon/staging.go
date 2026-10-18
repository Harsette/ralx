package daemon

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/Harsette/ralx/internal/store"
)

func mustJSON(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}

// staging holds media an agent sent to RalX for a later action (e.g. a social
// post, or a YouTube upload whose exact bytes the owner approves). Files live in
// RalX's private folder, keyed to the agent that uploaded them, and expire
// after a day. RalX hashes the bytes as they arrive so an approval can be
// bound to the exact file (its size and SHA-256).
type staging struct {
	dir string
	mu  sync.Mutex
	m   map[string]*staged
}

type staged struct {
	ID        string `json:"upload_id"`
	Name      string `json:"name"`
	MimeType  string `json:"mime_type"`
	Size      int64  `json:"size"`
	Offset    int64  `json:"offset"`
	Done      bool   `json:"done"`
	SHA256    string `json:"sha256,omitempty"`
	ChunkSize int    `json:"chunk_size"`

	agentID string
	path    string
	created time.Time
	hasher  hash.Hash
}

const (
	maxStaged      = 4 << 30  // per file
	maxStagedTotal = 12 << 30 // all staged files together (A12: bounded)
	maxStagedCount = 64
)

func newStaging(dir string) *staging {
	_ = os.MkdirAll(dir, 0o700)
	s := &staging{dir: dir, m: map[string]*staged{}}
	// Clear anything a previous run left behind (the in-memory index is gone).
	if entries, err := os.ReadDir(dir); err == nil {
		for _, e := range entries {
			_ = os.Remove(filepath.Join(dir, e.Name()))
		}
	}
	go s.gcLoop()
	return s
}

func (s *staging) gcLoop() {
	for {
		time.Sleep(10 * time.Minute)
		s.mu.Lock()
		s.gcLocked()
		s.mu.Unlock()
	}
}

func (s *staging) gcLocked() {
	for id, f := range s.m {
		if time.Since(f.created) > 24*time.Hour {
			_ = os.Remove(f.path)
			delete(s.m, id)
		}
	}
}

// totalsLocked returns the current staged byte count and file count.
func (s *staging) totalsLocked() (bytes int64, count int) {
	for _, f := range s.m {
		bytes += f.Size
		count++
	}
	return
}

func (s *staging) start(agentID, name, mime string, size int64) (*staged, error) {
	if size <= 0 || size > maxStaged {
		return nil, fmt.Errorf("size must be between 1 byte and %d bytes", int64(maxStaged))
	}
	name = filepath.Base(strings.ReplaceAll(name, "\\", "/"))
	if name == "." || name == "/" || name == "" {
		name = "file"
	}
	s.mu.Lock()
	s.gcLocked()
	bytes, count := s.totalsLocked()
	if count >= maxStagedCount || bytes+size > maxStagedTotal {
		s.mu.Unlock()
		return nil, errors.New("too much is staged right now; finish or wait for earlier uploads to expire")
	}
	id := store.NewID("stg_")
	f := &staged{ID: id, Name: name, MimeType: mime, Size: size, ChunkSize: 16 << 20, agentID: agentID,
		path: filepath.Join(s.dir, id), created: time.Now(), hasher: sha256.New()}
	s.m[id] = f
	s.mu.Unlock()
	if err := os.WriteFile(f.path, nil, 0o600); err != nil {
		s.mu.Lock()
		delete(s.m, id)
		s.mu.Unlock()
		return nil, err
	}
	return f, nil
}

func (s *staging) get(id, agentID string) (*staged, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f, ok := s.m[id]
	if !ok || f.agentID != agentID {
		return nil, errors.New("no such staged upload")
	}
	return f, nil
}

func (s *staging) put(id, agentID string, offset, length int64, body io.Reader) (*staged, error) {
	f, err := s.get(id, agentID)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	// A finished file is immutable: its bytes, size and hash are what an approval
	// is bound to, so nothing may append to it afterwards (Astra N1).
	if f.Done {
		return f, errors.New("upload already complete")
	}
	// Validate the chunk without overflow: offset must resume exactly, and the
	// length must fit the space left. f.Offset <= f.Size is an invariant, so the
	// subtraction can't underflow and offset+length can't overflow.
	if offset != f.Offset {
		return f, fmt.Errorf("offset mismatch: have %d", f.Offset)
	}
	if length <= 0 || length > f.Size-f.Offset {
		return f, fmt.Errorf("chunk length %d does not fit the remaining %d bytes", length, f.Size-f.Offset)
	}
	fh, err := os.OpenFile(f.path, os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return f, err
	}
	n, err := io.Copy(io.MultiWriter(fh, f.hasher), io.LimitReader(body, length))
	fh.Close()
	f.Offset += n
	if err != nil {
		return f, err
	}
	if n != length {
		return f, errors.New("short chunk")
	}
	if f.Offset == f.Size {
		f.Done = true
		f.SHA256 = hex.EncodeToString(f.hasher.Sum(nil))
	}
	return f, nil
}

func (s *staging) status(id, agentID string) (*staged, error) { return s.get(id, agentID) }

// StagedFile returns the private file path and identity of a finished staged
// upload owned by agentID. Used by native actions running inside the daemon.
func (s *staging) StagedFile(id, agentID string) (path, name, mimeType, sha string, size int64, err error) {
	f, e := s.get(id, agentID)
	if e != nil {
		return "", "", "", "", 0, e
	}
	if !f.Done {
		return "", "", "", "", 0, errors.New("staged upload is not finished")
	}
	return f.path, f.Name, f.MimeType, f.SHA256, f.Size, nil
}

// remove deletes a staged file once an action has consumed it.
func (s *staging) remove(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if f, ok := s.m[id]; ok {
		_ = os.Remove(f.path)
		delete(s.m, id)
	}
}
