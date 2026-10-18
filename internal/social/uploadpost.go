// Package social posts to every platform through one RalX key. Behind it,
// RalX holds the Upload-Post API key (never shown to agents) and calls
// Upload-Post's API; every public post waits for the owner's yes.
package social

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/Harsette/ralx/internal/actions"
	"github.com/Harsette/ralx/internal/redact"
	"github.com/Harsette/ralx/internal/store"
)

const (
	Credential = "uploadpost"
	baseURL    = "https://api.upload-post.com/api"
)

type Client struct {
	store *store.Store
	red   *redact.Redactor
	http  *http.Client
	Base  string
}

func New(s *store.Store, r *redact.Redactor) *Client {
	// Never follow redirects: the Authorization header carries the Upload-Post key,
	// and Go would replay it on a same-host (or downgraded-scheme) redirect. A 3xx
	// then surfaces as a non-2xx error instead (Astra5 P2, parity with Google/
	// upstream clients).
	return &Client{store: s, red: r, http: &http.Client{Timeout: 15 * time.Minute,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, Base: baseURL}
}

func (c *Client) key(ctx context.Context) (string, string, error) {
	cr, f, err := c.store.BoundSecret(ctx, Credential)
	if err != nil || f["api_key"] == "" {
		return "", "", errors.New("social posting isn't connected: the owner needs to add the Upload-Post API key in RalX")
	}
	c.red.Add(Credential+":api_key", f["api_key"])
	profile := ""
	profile, _ = cr.Meta["profile"].(string)
	return f["api_key"], profile, nil
}

func (c *Client) do(ctx context.Context, method, path string, body io.Reader, contentType string) (map[string]any, error) {
	key, _, err := c.key(ctx)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, method, c.Base+path, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Apikey "+key)
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, errors.New(c.red.String(err.Error()))
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	var out map[string]any
	_ = json.Unmarshal(data, &out)
	if resp.StatusCode/100 != 2 {
		msg := strings.TrimSpace(string(data))
		if len(msg) > 800 {
			msg = msg[:800]
		}
		return out, fmt.Errorf("upload-post %d: %s", resp.StatusCode, c.red.String(msg))
	}
	if out == nil {
		out = map[string]any{"raw": c.red.String(string(data))}
	}
	return out, nil
}

var platforms = []string{"x", "linkedin", "facebook", "instagram", "tiktok", "youtube", "threads", "pinterest", "bluesky", "reddit"}

func str(a map[string]any, k string) string    { s, _ := a[k].(string); return s }
func strs(a map[string]any, k string) []string { s, _ := a[k].([]string); return s }

// isPrivate reports whether a post provably reaches nobody else: only
// YouTube private videos and TikTok inbox drafts qualify.
func isPrivate(args map[string]any) bool {
	ps := strs(args, "platforms")
	if len(ps) == 0 || str(args, "scheduled_date") != "" {
		return false
	}
	for _, p := range ps {
		switch p {
		case "youtube":
			if str(args, "youtube_privacy") != "private" || str(args, "media_upload_id") == "" {
				return false
			}
		case "tiktok":
			if v, _ := args["tiktok_draft"].(bool); !v {
				return false
			}
		default:
			return false
		}
	}
	return true
}

func (c *Client) Actions() []*actions.Action {
	profileParam := actions.Param{Name: "profile", Type: "string", Pattern: `[A-Za-z0-9_.\-]{1,64}`, Description: "Upload-Post profile; empty = the owner's default"}
	return []*actions.Action{
		{
			Name: "social.accounts", Risk: actions.Read, Requires: []string{Credential},
			Description: "List the social profiles and which platforms are connected to each.",
			Params:      []actions.Param{},
			Native: func(ctx context.Context, env actions.Env, args map[string]any) (any, error) {
				out, err := c.do(ctx, "GET", "/uploadposts/users", nil, "")
				if err != nil {
					return nil, err
				}
				return summarizeProfiles(out), nil
			},
		},
		{
			Name: "social.post", Risk: actions.Write, GateReason: "posts", Requires: []string{Credential},
			Description:     "Post to one or more social platforms with one call. Public posts are held for the owner's approval; a private YouTube video or a TikTok draft runs straight away. For media, first upload the file with `ralx stage <file>` (or the MCP tool stage_file) and pass its upload id.",
			SummaryTemplate: "Post to {platforms}: \"{text}\"",
			GateFunc:        func(a map[string]any) bool { return !isPrivate(a) },
			Params: []actions.Param{
				{Name: "platforms", Type: "array", Required: true, Enum: platforms, Description: "e.g. [\"x\",\"linkedin\"]"},
				{Name: "text", Type: "string", Required: true, MaxLen: 10000, AllowLeadingDash: true, Description: "Post text (YouTube/Reddit: the title)"},
				{Name: "description", Type: "string", MaxLen: 10000, AllowLeadingDash: true, Description: "Longer description (YouTube, LinkedIn video, etc.)"},
				{Name: "media_upload_id", Type: "string", Pattern: `stg_[A-Za-z0-9_\-]{6,40}`, Description: "Staged photo or video"},
				{Name: "youtube_privacy", Type: "string", Enum: []string{"private", "unlisted", "public"}},
				{Name: "tiktok_draft", Type: "boolean", Default: false, Description: "Send to the TikTok inbox as a draft"},
				{Name: "scheduled_date", Type: "string", Pattern: `\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(:\d{2})?(Z|[+\-]\d{2}:\d{2})?`, Description: "ISO-8601; schedule instead of posting now"},
				{Name: "link_url", Type: "string", Pattern: `https://[^\s]{3,1000}`},
				{Name: "facebook_page_id", Type: "string", Pattern: `[0-9]{5,30}`},
				{Name: "pinterest_board_id", Type: "string", Pattern: `[0-9]{5,30}`},
				profileParam,
			},
			Native: func(ctx context.Context, env actions.Env, args map[string]any) (any, error) {
				return c.post(ctx, env, args)
			},
		},
		{
			Name: "social.status", Risk: actions.Read, Requires: []string{Credential},
			Description: "Check an async or scheduled post by request_id or job_id.",
			Params: []actions.Param{
				{Name: "request_id", Type: "string", Pattern: `[A-Za-z0-9_\-]{4,100}`},
				{Name: "job_id", Type: "string", Pattern: `[A-Za-z0-9_\-]{4,100}`},
			},
			Native: func(ctx context.Context, env actions.Env, args map[string]any) (any, error) {
				q := url.Values{}
				if v := str(args, "request_id"); v != "" {
					q.Set("request_id", v)
				} else if v := str(args, "job_id"); v != "" {
					q.Set("job_id", v)
				} else {
					return nil, errors.New("give request_id or job_id")
				}
				return c.do(ctx, "GET", "/uploadposts/status?"+q.Encode(), nil, "")
			},
		},
		{
			Name: "social.history", Risk: actions.Read, Requires: []string{Credential},
			Description: "Recent posts made through RalX/Upload-Post, with post URLs.",
			Params: []actions.Param{
				{Name: "limit", Type: "integer", Enum: nil, Min: fp(10), Max: fp(100), Default: int64(20)},
				{Name: "platform", Type: "string", Enum: platforms},
			},
			Native: func(ctx context.Context, env actions.Env, args map[string]any) (any, error) {
				q := url.Values{"limit": {fmt.Sprint(args["limit"])}}
				if p := str(args, "platform"); p != "" {
					q.Set("platform", p)
				}
				return c.do(ctx, "GET", "/uploadposts/history?"+q.Encode(), nil, "")
			},
		},
		{
			Name: "social.scheduled", Risk: actions.Read, Requires: []string{Credential},
			Description: "List scheduled (not yet published) posts.",
			Params:      []actions.Param{},
			Native: func(ctx context.Context, env actions.Env, args map[string]any) (any, error) {
				return c.do(ctx, "GET", "/uploadposts/schedule", nil, "")
			},
		},
		{
			Name: "social.cancel_scheduled", Risk: actions.Gated, GateReason: "deletes", Requires: []string{Credential},
			Description:     "Cancel a scheduled post before it goes out (the credit is refunded). Held for the owner's approval.",
			SummaryTemplate: "Cancel scheduled post {job_id}",
			Params:          []actions.Param{{Name: "job_id", Type: "string", Required: true, Pattern: `[A-Za-z0-9_\-]{4,100}`}},
			Native: func(ctx context.Context, env actions.Env, args map[string]any) (any, error) {
				return c.do(ctx, "DELETE", "/uploadposts/schedule/"+url.PathEscape(str(args, "job_id")), nil, "")
			},
		},
		{
			Name: "social.unpublish", Risk: actions.Gated, GateReason: "deletes", Requires: []string{Credential},
			Description:     "Delete a published post (YouTube, X, LinkedIn, Facebook, Pinterest, Bluesky). Held for the owner's approval.",
			SummaryTemplate: "Delete {platform} post {post_id}",
			Params: []actions.Param{
				{Name: "platform", Type: "string", Required: true, Enum: []string{"youtube", "x", "linkedin", "facebook", "pinterest", "bluesky"}},
				{Name: "post_id", Type: "string", Required: true, MaxLen: 300},
				profileParam,
			},
			Native: func(ctx context.Context, env actions.Env, args map[string]any) (any, error) {
				_, profile, err := c.key(ctx)
				if err != nil {
					return nil, err
				}
				if p := str(args, "profile"); p != "" {
					profile = p
				}
				body, _ := json.Marshal(map[string]string{"platform": str(args, "platform"), "user": profile, "post_id": str(args, "post_id")})
				return c.do(ctx, "POST", "/uploadposts/posts/unpublish", strings.NewReader(string(body)), "application/json")
			},
		},
	}
}

func fp(v float64) *float64 { return &v }

// summarizeProfiles keeps names and connected platforms; it drops connect
// links and anything token-like.
func summarizeProfiles(out map[string]any) map[string]any {
	profiles, _ := out["profiles"].([]any)
	var list []map[string]any
	for _, p := range profiles {
		pm, _ := p.(map[string]any)
		if pm == nil {
			continue
		}
		connected := map[string]any{}
		if sa, ok := pm["social_accounts"].(map[string]any); ok {
			for plat, v := range sa {
				if m, ok := v.(map[string]any); ok {
					connected[plat] = map[string]any{"handle": m["handle"], "display_name": m["display_name"], "reauth_required": m["reauth_required"]}
				}
			}
		}
		list = append(list, map[string]any{"profile": pm["username"], "connected": connected})
	}
	return map[string]any{"profiles": list, "plan": out["plan"], "limit": out["limit"]}
}

func (c *Client) post(ctx context.Context, env actions.Env, args map[string]any) (any, error) {
	_, profile, err := c.key(ctx)
	if err != nil {
		return nil, err
	}
	if p := str(args, "profile"); p != "" {
		profile = p
	}
	if profile == "" {
		return nil, errors.New("no Upload-Post profile set; the owner sets the default profile on the credential in RalX")
	}
	ps := strs(args, "platforms")
	endpoint := "/upload_text"
	var mediaPath, mediaName, mediaField string
	if id := str(args, "media_upload_id"); id != "" {
		p, name, mime, _, _, err := env.StagedFile(id)
		if err != nil {
			return nil, err
		}
		mediaPath, mediaName = p, name
		switch {
		case strings.HasPrefix(mime, "video/"):
			endpoint, mediaField = "/upload", "video"
		case strings.HasPrefix(mime, "image/"):
			endpoint, mediaField = "/upload_photos", "photos[]"
		default:
			return nil, fmt.Errorf("media must be an image or video (got %q)", mime)
		}
	}
	for _, p := range ps {
		if endpoint == "/upload_text" && (p == "instagram" || p == "tiktok" || p == "youtube" || p == "pinterest") {
			return nil, fmt.Errorf("%s needs a photo or video (stage one and pass media_upload_id)", p)
		}
	}
	fields := [][2]string{{"user", profile}, {"title", str(args, "text")}}
	for _, p := range ps {
		fields = append(fields, [2]string{"platform[]", p})
	}
	add := func(k, v string) {
		if v != "" {
			fields = append(fields, [2]string{k, v})
		}
	}
	add("description", str(args, "description"))
	add("scheduled_date", str(args, "scheduled_date"))
	add("link_url", str(args, "link_url"))
	add("facebook_page_id", str(args, "facebook_page_id"))
	add("pinterest_board_id", str(args, "pinterest_board_id"))
	add("privacyStatus", str(args, "youtube_privacy"))
	if d, _ := args["tiktok_draft"].(bool); d {
		add("post_mode", "MEDIA_UPLOAD")
	}
	if mediaPath != "" {
		add("async_upload", "true")
	}

	pr, pw := io.Pipe()
	mw := multipart.NewWriter(pw)
	go func() {
		var werr error
		defer func() { pw.CloseWithError(werr) }()
		for _, kv := range fields {
			if werr = mw.WriteField(kv[0], kv[1]); werr != nil {
				return
			}
		}
		if mediaPath != "" {
			fh, err := os.Open(mediaPath)
			if err != nil {
				werr = err
				return
			}
			defer fh.Close()
			part, err := mw.CreateFormFile(mediaField, mediaName)
			if err != nil {
				werr = err
				return
			}
			if _, werr = io.Copy(part, fh); werr != nil {
				return
			}
		}
		werr = mw.Close()
	}()
	return c.do(ctx, "POST", endpoint, pr, mw.FormDataContentType())
}
