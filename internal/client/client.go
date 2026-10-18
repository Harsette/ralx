// Package client is how the ralx CLI and the MCP server talk to the daemon.
// It holds only the agent's RalX key (a revocable stand-in), never a real
// credential, and it reads local files as the agent so the daemon never has
// to touch the agent's disk.
package client

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const DefaultURL = "http://127.0.0.1:7317"

type Client struct {
	URL   string
	Key   string
	HTTP  *http.Client
	Admin bool // talking over the admin pipe
}

// KeyFile is the default per-user location of the agent key.
func KeyFile() string {
	if f := os.Getenv("RALX_AGENT_KEY_FILE"); f != "" {
		return f
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".ralx", "agent.key")
}

// Identity is one agent saved on this computer: its key and the RalX address
// the key belongs to, kept in one file so a key is never paired with another
// hub's address.
type Identity struct {
	URL       string `json:"url"`
	Key       string `json:"key"`
	KeyDigest string `json:"key_sha256"`
}

// KeyDigest identifies a key without revealing it.
func KeyDigest(key string) string {
	h := sha256.Sum256([]byte(key))
	return hex.EncodeToString(h[:])
}

// ReadIdentity reads an agent key file: a JSON identity written by `ralx
// enroll`, or a bare key written by `ralx admin install`, whose URL is then
// empty (the default hub, or RALX_URL).
func ReadIdentity(path string) (Identity, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Identity{}, err
	}
	s := strings.TrimSpace(string(b))
	if !strings.HasPrefix(s, "{") {
		return Identity{Key: s, KeyDigest: KeyDigest(s)}, nil
	}
	var id Identity
	if json.Unmarshal([]byte(s), &id) != nil || id.Key == "" || id.URL == "" || id.KeyDigest != KeyDigest(id.Key) {
		return Identity{}, fmt.Errorf("%s is not a valid RalX agent file", filepath.Base(path))
	}
	id.URL = strings.TrimRight(id.URL, "/")
	return id, nil
}

// New builds an agent client from env/defaults. A key from an enrolled
// identity file only ever goes to that identity's own address.
func New() *Client {
	u := os.Getenv("RALX_URL")
	if u == "" {
		u = DefaultURL
	}
	key := strings.TrimSpace(os.Getenv("RALX_AGENT_KEY"))
	if key == "" {
		if id, err := ReadIdentity(KeyFile()); err == nil {
			key = id.Key
			if id.URL != "" {
				u = id.URL
			}
		}
	}
	return &Client{URL: strings.TrimRight(u, "/"), Key: key, HTTP: &http.Client{Timeout: 0}}
}

type APIError struct {
	Status int
	Msg    string
	Body   map[string]any
}

func (e *APIError) Error() string { return e.Msg }

func (c *Client) req(ctx context.Context, method, path string, body io.Reader, hdr map[string]string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, c.URL+path, body)
	if err != nil {
		return nil, err
	}
	if c.Key != "" && !c.Admin {
		req.Header.Set("Authorization", "Bearer "+c.Key)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		if strings.Contains(err.Error(), "refused") || strings.Contains(err.Error(), "No connection could be made") {
			return nil, errors.New("RalX isn't running on this computer (start it with `ralx daemon`, or install the service with `ralx admin install`)")
		}
		return nil, err
	}
	return resp, nil
}

// JSON performs a JSON request and decodes the JSON response. extra adds
// request headers.
func (c *Client) JSON(ctx context.Context, method, path string, in any, out any, extra ...map[string]string) (int, error) {
	var body io.Reader
	hdr := map[string]string{}
	for _, m := range extra {
		for k, v := range m {
			hdr[k] = v
		}
	}
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return 0, err
		}
		body = bytes.NewReader(b)
		hdr["Content-Type"] = "application/json"
	}
	resp, err := c.req(ctx, method, path, body, hdr)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if resp.StatusCode/100 != 2 {
		var m map[string]any
		_ = json.Unmarshal(data, &m)
		msg, _ := m["error"].(string)
		if msg == "" {
			msg = fmt.Sprintf("RalX returned %d", resp.StatusCode)
		}
		return resp.StatusCode, &APIError{Status: resp.StatusCode, Msg: msg, Body: m}
	}
	if out != nil {
		dec := json.NewDecoder(bytes.NewReader(data))
		dec.UseNumber()
		if err := dec.Decode(out); err != nil {
			return resp.StatusCode, err
		}
	}
	return resp.StatusCode, nil
}

func (c *Client) Call(ctx context.Context, action string, args map[string]any) (int, map[string]any, error) {
	var out map[string]any
	code, err := c.JSON(ctx, "POST", "/v1/actions/"+url.PathEscape(action), map[string]any{"args": args}, &out)
	return code, out, err
}

func (c *Client) WaitApproval(ctx context.Context, id string, total time.Duration) (map[string]any, error) {
	deadline := time.Now().Add(total)
	for {
		wait := 60
		if rem := time.Until(deadline); rem < 60*time.Second {
			wait = int(rem.Seconds())
		}
		if wait < 1 {
			wait = 1
		}
		var out map[string]any
		if _, err := c.JSON(ctx, "GET", "/v1/approvals/"+url.PathEscape(id)+"?wait="+strconv.Itoa(wait), nil, &out); err != nil {
			return nil, err
		}
		st, _ := out["status"].(string)
		if (st != "pending" && st != "approved") || time.Now().After(deadline) {
			return out, nil
		}
	}
}

// ---------- uploads ----------

type Progress func(sent, total int64)

type Upload struct {
	ID        string         `json:"upload_id"`
	Target    string         `json:"target"`
	Name      string         `json:"name"`
	Size      int64          `json:"size"`
	Offset    int64          `json:"offset"`
	Done      bool           `json:"done"`
	Result    map[string]any `json:"result"`
	ChunkSize int            `json:"chunk_size"`
}

// StartUpload opens an upload session. If the destination needs the owner's
// approval (a shared Drive folder), it returns the approval id instead.
func (c *Client) StartUpload(ctx context.Context, meta map[string]any) (*Upload, string, error) {
	var out map[string]any
	code, err := c.JSON(ctx, "POST", "/v1/uploads", meta, &out)
	if err != nil {
		return nil, "", err
	}
	if code == 202 {
		id, _ := out["approval_id"].(string)
		return nil, id, nil
	}
	return decodeUpload(out)
}

func decodeUpload(m map[string]any) (*Upload, string, error) {
	b, _ := json.Marshal(m)
	var u Upload
	if err := json.Unmarshal(b, &u); err != nil {
		return nil, "", err
	}
	if u.ID == "" {
		return nil, "", errors.New("RalX did not return an upload id")
	}
	return &u, "", nil
}

// SendFile streams path to an open upload session in chunks, resuming after
// network errors.
func (c *Client) SendFile(ctx context.Context, u *Upload, path string, progress Progress) (*Upload, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	chunk := int64(u.ChunkSize)
	if chunk <= 0 {
		chunk = 16 << 20
	}
	buf := make([]byte, chunk)
	retries := 0
	for !u.Done {
		n := chunk
		if u.Size-u.Offset < n {
			n = u.Size - u.Offset
		}
		if _, err := f.ReadAt(buf[:n], u.Offset); err != nil && !errors.Is(err, io.EOF) {
			return u, err
		}
		resp, err := c.req(ctx, "PUT", "/v1/uploads/"+url.PathEscape(u.ID), bytes.NewReader(buf[:n]),
			map[string]string{"X-RalX-Offset": strconv.FormatInt(u.Offset, 10), "Content-Type": "application/octet-stream"})
		var out map[string]any
		ok := false
		if err == nil {
			data, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			_ = json.Unmarshal(data, &out)
			if resp.StatusCode == 200 {
				ok = true
			} else if msg, _ := out["error"].(string); resp.StatusCode == 404 || strings.Contains(msg, "expired") {
				return u, errors.New(msg)
			} else {
				err = errors.New(msg)
			}
		}
		if ok {
			nu, _, derr := decodeUpload(out)
			if derr != nil {
				return u, derr
			}
			u, retries = nu, 0
			if progress != nil {
				progress(u.Offset, u.Size)
			}
			continue
		}
		retries++
		if retries > 8 {
			return u, fmt.Errorf("upload failed after retries: %v", err)
		}
		time.Sleep(time.Duration(retries) * time.Second)
		// Ask where Google actually is, then resume from there.
		var st map[string]any
		if _, serr := c.JSON(ctx, "GET", "/v1/uploads/"+url.PathEscape(u.ID), nil, &st); serr == nil {
			if nu, _, derr := decodeUpload(st); derr == nil {
				u = nu
			}
		}
	}
	return u, nil
}

func GuessMime(path string) string {
	if t := mime.TypeByExtension(strings.ToLower(filepath.Ext(path))); t != "" {
		return strings.Split(t, ";")[0]
	}
	return "application/octet-stream"
}

// Download streams a Drive file into dest.
func (c *Client) Download(ctx context.Context, fileID, dest string, progress Progress) (int64, error) {
	resp, err := c.req(ctx, "GET", "/v1/drive/files/"+url.PathEscape(fileID)+"/content", nil, nil)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		var m map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&m)
		msg, _ := m["error"].(string)
		return 0, errors.New(msg)
	}
	if st, err := os.Stat(dest); err == nil && st.IsDir() {
		name, _ := url.PathUnescape(resp.Header.Get("X-RalX-Filename"))
		name = filepath.Base(strings.ReplaceAll(name, "\\", "/"))
		if name == "" || name == "." || name == "/" {
			name = fileID
		}
		dest = filepath.Join(dest, name)
	}
	tmp := dest + ".part"
	f, err := os.Create(tmp)
	if err != nil {
		return 0, err
	}
	total, _ := strconv.ParseInt(resp.Header.Get("Content-Length"), 10, 64)
	var written int64
	buf := make([]byte, 1<<20)
	for {
		n, rerr := resp.Body.Read(buf)
		if n > 0 {
			if _, werr := f.Write(buf[:n]); werr != nil {
				f.Close()
				return written, werr
			}
			written += int64(n)
			if progress != nil {
				progress(written, total)
			}
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			f.Close()
			return written, rerr
		}
	}
	f.Close()
	return written, os.Rename(tmp, dest)
}
