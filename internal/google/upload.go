package google

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Harsette/ralx/internal/store"
)

// ChunkSize is what clients should send per PUT (a multiple of 256 KiB, as
// Google's resumable protocol requires for all but the last chunk).
const ChunkSize = 16 << 20

const chunkQuantum = 256 << 10

// Upload is one resumable upload session. The Google session URI is itself a
// bearer capability, so it never leaves the daemon; agents get an opaque ID.
type Upload struct {
	ID        string         `json:"upload_id"`
	Target    string         `json:"target"`
	Name      string         `json:"name"`
	Size      int64          `json:"size"`
	Offset    int64          `json:"offset"`
	Done      bool           `json:"done"`
	Result    map[string]any `json:"result,omitempty"`
	ChunkSize int            `json:"chunk_size"`

	account    string
	agent      string
	sessionURI string
	created    time.Time
	mu         sync.Mutex
}

type uploads struct {
	mu sync.Mutex
	m  map[string]*Upload
}

var ups = &uploads{m: map[string]*Upload{}}

// StartUpload opens a Google resumable session for a Drive file or a YouTube
// video. meta is the Drive file resource or the YouTube video resource.
func (b *Broker) StartUpload(ctx context.Context, target, account, agent string, size int64, mimeType string, meta map[string]any) (*Upload, error) {
	if size <= 0 {
		return nil, errors.New("size must be positive")
	}
	if mimeType == "" {
		mimeType = "application/octet-stream"
	}
	if account == "" {
		account = b.DefaultAccountFor(target)
	}
	var endpoint string
	switch target {
	case "drive":
		endpoint = "https://www.googleapis.com/upload/drive/v3/files?uploadType=resumable&supportsAllDrives=true&fields=id,name,size,mimeType,md5Checksum,webViewLink,parents"
	case "youtube":
		endpoint = "https://www.googleapis.com/upload/youtube/v3/videos?uploadType=resumable&part=snippet,status"
	default:
		return nil, fmt.Errorf("unknown upload target %q", target)
	}
	metaJSON, _ := json.Marshal(meta)
	resp, err := b.Do(ctx, account, func(tok string) (*http.Request, error) {
		req, err := http.NewRequest("POST", endpoint, strings.NewReader(string(metaJSON)))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json; charset=UTF-8")
		req.Header.Set("X-Upload-Content-Type", mimeType)
		req.Header.Set("X-Upload-Content-Length", strconv.FormatInt(size, 10))
		return req, nil
	})
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
		return nil, &APIError{Status: resp.StatusCode, Body: b.Redactor.String(string(body))}
	}
	loc := resp.Header.Get("Location")
	if loc == "" {
		return nil, errors.New("google did not return an upload session")
	}
	// The session URI decides where the account's bearer token is sent on every
	// chunk. A provider-supplied Location must be an approved Google HTTPS origin,
	// never an attacker-chosen host (Astra R10).
	if err := b.checkUploadURL(loc); err != nil {
		return nil, err
	}
	// The session URI is itself a bearer capability: anyone holding it can
	// upload to this file without RalX. Register it so it is scrubbed from any
	// error or output that reaches an agent, and keep it out of JSON (below).
	b.Redactor.Add("google:upload-session", loc)
	name, _ := meta["name"].(string)
	if sn, ok := meta["snippet"].(map[string]any); ok {
		name, _ = sn["title"].(string)
	}
	u := &Upload{ID: store.NewID("up_"), Target: target, Name: name, Size: size, ChunkSize: ChunkSize,
		account: account, agent: agent, sessionURI: loc, created: time.Now()}
	ups.mu.Lock()
	for id, old := range ups.m {
		if time.Since(old.created) > 7*24*time.Hour {
			delete(ups.m, id)
		}
	}
	ups.m[u.ID] = u
	ups.mu.Unlock()
	return u, nil
}

// checkUploadURL requires a resumable session URL to be HTTPS and (in
// production) on a googleapis.com host, so the account bearer can't be sent to
// an arbitrary origin named in the Location header (Astra R10).
func (b *Broker) checkUploadURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return errors.New("google returned an unusable upload session URL")
	}
	// Userinfo or a non-standard port can smuggle the bearer to the wrong place
	// even on a *.googleapis.com host (Astra A14).
	if u.User != nil {
		return errors.New("upload session URL must not carry userinfo")
	}
	if p := u.Port(); p != "" && p != "443" {
		return fmt.Errorf("upload session URL must use port 443, not %q", p)
	}
	if b.TrustAnyUploadHost {
		return nil
	}
	host := strings.ToLower(u.Hostname())
	if host == "googleapis.com" || strings.HasSuffix(host, ".googleapis.com") {
		return nil
	}
	return fmt.Errorf("refusing an upload session on a non-Google host %q", host)
}

func (b *Broker) getUpload(id, agent string) (*Upload, error) {
	ups.mu.Lock()
	u, ok := ups.m[id]
	ups.mu.Unlock()
	if !ok || u.agent != agent {
		return nil, store.ErrNotFound
	}
	return u, nil
}

func (u *Upload) snapshot() *Upload {
	return &Upload{ID: u.ID, Target: u.Target, Name: u.Name, Size: u.Size, Offset: u.Offset, Done: u.Done, Result: u.Result, ChunkSize: u.ChunkSize}
}

// PutChunk streams one chunk from the agent straight through to Google.
func (b *Broker) PutChunk(ctx context.Context, id, agent string, offset, length int64, body io.Reader) (*Upload, error) {
	u, err := b.getUpload(id, agent)
	if err != nil {
		return nil, err
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.Done {
		return u.snapshot(), nil
	}
	if offset != u.Offset {
		return u.snapshot(), fmt.Errorf("offset mismatch: RalX has %d bytes, chunk starts at %d", u.Offset, offset)
	}
	if length <= 0 || offset+length > u.Size {
		return u.snapshot(), errors.New("chunk is outside the file size")
	}
	last := offset+length == u.Size
	if !last && length%chunkQuantum != 0 {
		return u.snapshot(), errors.New("non-final chunks must be a multiple of 256 KiB")
	}
	// Re-validate the stored session URI before every authenticated use, so the
	// account bearer is only ever sent to an approved Google HTTPS origin (Astra
	// A14 defence in depth).
	if err := b.checkUploadURL(u.sessionURI); err != nil {
		return u.snapshot(), err
	}
	resp, err := b.Do(ctx, u.account, func(tok string) (*http.Request, error) {
		req, err := http.NewRequest("PUT", u.sessionURI, io.LimitReader(body, length))
		if err != nil {
			return nil, err
		}
		req.ContentLength = length
		req.Header.Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", offset, offset+length-1, u.Size))
		return req, nil
	})
	if err != nil {
		return u.snapshot(), err
	}
	defer resp.Body.Close()
	aerr := b.absorb(u, resp)
	return u.snapshot(), aerr
}

func (b *Broker) absorb(u *Upload, resp *http.Response) error {
	switch {
	case resp.StatusCode == 308:
		u.Offset = 0
		if r := resp.Header.Get("Range"); r != "" {
			if i := strings.LastIndexByte(r, '-'); i >= 0 {
				if n, err := strconv.ParseInt(r[i+1:], 10, 64); err == nil {
					u.Offset = n + 1
				}
			}
		}
		return nil
	case resp.StatusCode == 200 || resp.StatusCode == 201:
		var out map[string]any
		_ = json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&out)
		u.Offset, u.Done, u.Result = u.Size, true, out
		return nil
	case resp.StatusCode == 404 || resp.StatusCode == 410:
		return errors.New("Google expired this upload session; start the upload again")
	default:
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
		return &APIError{Status: resp.StatusCode, Body: b.Redactor.String(string(body))}
	}
}

// UploadStatus asks Google how many bytes it has, so a client can resume
// after a dropped connection.
func (b *Broker) UploadStatus(ctx context.Context, id, agent string) (*Upload, error) {
	u, err := b.getUpload(id, agent)
	if err != nil {
		return nil, err
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.Done {
		return u.snapshot(), nil
	}
	if err := b.checkUploadURL(u.sessionURI); err != nil {
		return u.snapshot(), err
	}
	resp, err := b.Do(ctx, u.account, func(tok string) (*http.Request, error) {
		req, err := http.NewRequest("PUT", u.sessionURI, nil)
		if err != nil {
			return nil, err
		}
		req.ContentLength = 0
		req.Header.Set("Content-Range", fmt.Sprintf("bytes */%d", u.Size))
		return req, nil
	})
	if err != nil {
		return u.snapshot(), err
	}
	defer resp.Body.Close()
	aerr := b.absorb(u, resp)
	return u.snapshot(), aerr
}

// DestinationShared reports whether a Drive folder is shared with anyone besides
// the owner (so a file placed in it would be exposed to others). It returns a
// one-line recipient summary for the approval card AND a canonical audience
// fingerprint that an approval is bound to: a display string collapses distinct
// audiences ("a shared drive", "a whole domain") so different recipient sets
// would compare equal and let an approved upload reach a changed audience (Astra
// A4/A5). The fingerprint instead encodes the actual, sorted permission set
// (type, role, email, domain, discovery scope, drive id, ownership). An unknown
// folder, or one whose full audience can't be resolved, is treated as shared
// with an empty fingerprint, which never matches a recheck, so the upload is
// refused rather than sent to an unverifiable audience (fail safe).
func (b *Broker) DestinationShared(ctx context.Context, account, folderID string) (shared bool, summary string, fingerprint string, err error) {
	if folderID == "" || folderID == "root" {
		return false, "", "", nil // the account's own My Drive root
	}
	var meta struct {
		Name                         string `json:"name"`
		Shared                       bool   `json:"shared"`
		OwnedByMe                    bool   `json:"ownedByMe"`
		DriveID                      string `json:"driveId"`
		InheritedPermissionsDisabled bool   `json:"inheritedPermissionsDisabled"`
	}
	if err := b.JSON(ctx, account, "GET", "https://www.googleapis.com/drive/v3/files/"+url.PathEscape(folderID)+"?supportsAllDrives=true&fields=name,shared,ownedByMe,driveId,inheritedPermissionsDisabled", nil, &meta); err != nil {
		return true, "", "", err // can't read metadata -> gate it, empty fingerprint never matches
	}
	// The real audience lives in permissions.list, NOT files.get: Drive omits
	// `permissions` from files.get for items in a shared drive, and for any item the
	// caller can't share. Read the full paginated permission set and fail closed if
	// it can't be read, so the fingerprint reflects who can actually see the file
	// (Daru6 P1-2 — the earlier files.get-embedded version was blind to the real API).
	perms, perr := b.listPermissions(ctx, account, folderID)
	if perr != nil {
		return true, "a Drive folder (its audience could not be resolved)", "", perr
	}
	// permissions.list always returns at least the owner/requester for a folder we
	// can upload to; an empty set means the audience wasn't really resolved (e.g. an
	// unread body that decoded to no permissions). Refuse rather than bind an empty
	// audience that would match on recheck (Daru6 P1).
	if len(perms) == 0 {
		return true, "a Drive folder (its audience could not be resolved)", "", errors.New("drive returned no permissions for the destination")
	}
	var parts, others []string
	for _, p := range perms {
		email := strings.ToLower(strings.TrimSpace(p.EmailAddress))
		domain := strings.ToLower(strings.TrimSpace(p.Domain))
		// Include `view` (the "published"/limited-access distinction) and the unique
		// grantee `id`, so a metadata-only reader gaining content access, or a
		// different principal reusing the same email, both change the fingerprint
		// (Daru6 P1 + self-review).
		parts = append(parts, strings.Join([]string{p.Type, p.Role, email, domain, p.View, p.ID, fmt.Sprint(p.AllowFileDiscovery)}, "\x1f"))
		if p.Role == "owner" {
			continue // the owner's own access isn't "sharing with someone else"
		}
		switch {
		case p.Type == "anyone":
			others = append(others, "anyone with the link")
		case email != "":
			others = append(others, email)
		case p.Type == "domain" && domain != "":
			others = append(others, "the "+domain+" domain")
		case p.Type == "domain":
			others = append(others, "a whole domain")
		}
	}
	sort.Strings(parts)
	fp := "owned=" + fmt.Sprint(meta.OwnedByMe) + ";drive=" + meta.DriveID +
		";inhDisabled=" + fmt.Sprint(meta.InheritedPermissionsDisabled) + ";perms=" + strings.Join(parts, "|")
	if meta.DriveID == "" && meta.OwnedByMe && !meta.Shared && len(others) == 0 {
		return false, "", "", nil // an own, unshared My Drive folder
	}
	switch {
	case meta.DriveID != "":
		summary = "a shared drive"
	case !meta.OwnedByMe:
		summary = "a folder you don't own"
	default:
		summary = strings.Join(others, ", ")
	}
	if len(others) > 0 && meta.DriveID != "" || len(others) > 0 && !meta.OwnedByMe {
		summary += " (" + strings.Join(others, ", ") + ")"
	}
	if summary == "" {
		summary = "others"
	}
	return true, summary, fp, nil
}

type drivePerm struct {
	Type               string `json:"type"`
	Role               string `json:"role"`
	EmailAddress       string `json:"emailAddress"`
	Domain             string `json:"domain"`
	View               string `json:"view"`
	AllowFileDiscovery bool   `json:"allowFileDiscovery"`
	ID                 string `json:"id"`
}

// listPermissions reads the full, paginated permission set of a Drive item via
// permissions.list (supportsAllDrives), which is the only API surface that returns
// a shared drive's or inherited membership (Daru6 P1-2).
func (b *Broker) listPermissions(ctx context.Context, account, fileID string) ([]drivePerm, error) {
	var out []drivePerm
	page := ""
	for i := 0; i < 50; i++ { // page cap: 50*100 = 5000 permissions
		u := "https://www.googleapis.com/drive/v3/files/" + url.PathEscape(fileID) +
			"/permissions?supportsAllDrives=true&pageSize=100&fields=permissions(type,role,emailAddress,domain,view,allowFileDiscovery,id),nextPageToken"
		if page != "" {
			u += "&pageToken=" + url.QueryEscape(page)
		}
		var resp struct {
			Permissions   []drivePerm `json:"permissions"`
			NextPageToken string      `json:"nextPageToken"`
		}
		if err := b.JSON(ctx, account, "GET", u, nil, &resp); err != nil {
			return nil, err
		}
		out = append(out, resp.Permissions...)
		if resp.NextPageToken == "" {
			return out, nil
		}
		page = resp.NextPageToken
	}
	return out, errors.New("drive folder has more permissions than RalX will page through")
}

// Download streams a Drive file's bytes to w.
func (b *Broker) Download(ctx context.Context, account, fileID string, w http.ResponseWriter) error {
	if account == "" {
		account = b.DefaultAccountFor("drive")
	}
	var meta struct {
		Name     string `json:"name"`
		MimeType string `json:"mimeType"`
		Size     string `json:"size"`
	}
	if err := b.JSON(ctx, account, "GET", "https://www.googleapis.com/drive/v3/files/"+fileID+"?supportsAllDrives=true&fields=name,mimeType,size", nil, &meta); err != nil {
		return err
	}
	if strings.HasPrefix(meta.MimeType, "application/vnd.google-apps.") {
		return errors.New("this is a Google Docs/Sheets/Slides file; export it instead of downloading")
	}
	resp, err := b.Do(ctx, account, func(tok string) (*http.Request, error) {
		return http.NewRequest("GET", "https://www.googleapis.com/drive/v3/files/"+fileID+"?alt=media&supportsAllDrives=true", nil)
	})
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
		return &APIError{Status: resp.StatusCode, Body: b.Redactor.String(string(body))}
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	safeName := b.Redactor.String(meta.Name)
	// Buffer the whole file (up to a cap) and deep-scan it: a file whose bytes
	// reconstruct a vault secret under any recognised transform (base64/base32
	// around a secret, gzip, percent, split across a flush boundary) is withheld
	// whole (Astra A2/A5). Over the cap we must NOT fall back to streaming raw
	// bytes — that failed open on a secret past a 16 MiB filler (Astra5). We
	// withhold instead (fail closed); a file too large to scan safely can be
	// fetched through an owner-approved path. The cap is generous so ordinary
	// documents and media still download.
	const scanCap = 64 << 20
	buf, err := io.ReadAll(io.LimitReader(resp.Body, scanCap+1))
	if err != nil {
		return err
	}
	if len(buf) > scanCap {
		// Too large to buffer-and-scan: withhold the body AND the filename — we can't
		// prove the name isn't half of a split with the unscanned body (Astra5/Astra7).
		w.Header().Set("X-RalX-Filename", "withheld")
		w.Header().Set("X-RalX-Withheld", "too-large-to-scan")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "[REDACTED: file too large for RalX to scan for credentials before release; download it through an owner-approved path]")
		return nil
	}
	// Check the filename and body TOGETHER: a secret split with half in the
	// X-RalX-Filename header and half in the body passes two independent checks, but the
	// agent concatenates them (Astra7 self-review filename/body split). If the name alone,
	// the body alone, or their concatenation in either order reconstructs a secret,
	// withhold BOTH. URL-escaping the name is reversible, so it is deep-checked first.
	body := string(buf)
	if b.Redactor.DeepContainsSecret(safeName) || b.Redactor.DeepContainsSecret(body) ||
		b.Redactor.DeepContainsSecret(safeName+body) || b.Redactor.DeepContainsSecret(body+safeName) {
		w.Header().Set("X-RalX-Filename", "withheld")
		w.Header().Set("X-RalX-Withheld", "credential")
		_, _ = io.WriteString(w, "[REDACTED: file withheld — its contents reconstruct a credential]")
		return nil
	}
	w.Header().Set("X-RalX-Filename", url.PathEscape(safeName))
	_, err = w.Write(b.Redactor.Bytes(buf))
	return err
}
