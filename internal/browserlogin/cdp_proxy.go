package browserlogin

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"sync"
	"time"

	"github.com/chromedp/cdproto"
	"github.com/chromedp/cdproto/target"
	"github.com/chromedp/chromedp"
	"github.com/coder/websocket"
)

// Chrome has no listening debugging socket. Only these inherited anonymous
// pipes reach it. Each websocket gets its own flattened browser session, so
// independent CDP clients keep separate ids, subscriptions and child sessions.
type cdpPeer struct {
	ctx    context.Context
	cancel context.CancelFunc
	ws     *websocket.Conn
	root   target.SessionID
	out    chan *cdproto.Message
}
type cdpPending struct {
	peer    *cdpPeer
	id      int64
	session target.SessionID
	attach  chan *cdproto.Message
}
type cdpProxy struct {
	ctx      context.Context
	cancel   context.CancelFunc
	pipe     chromedp.Transport
	mu       sync.Mutex
	next     int64
	pending  map[int64]cdpPending
	sessions map[target.SessionID]*cdpPeer
	peers    map[*cdpPeer]bool
}

func startPipeBrowser(executable, profile string) (string, func(), error) {
	childRead, parentWrite, e := os.Pipe()
	if e != nil {
		return "", nil, e
	}
	parentRead, childWrite, e := os.Pipe()
	if e != nil {
		childRead.Close()
		parentWrite.Close()
		return "", nil, e
	}
	files := []*os.File{childRead, parentWrite, parentRead, childWrite}
	closeFiles := func() {
		for _, f := range files {
			_ = f.Close()
		}
	}
	cmd := exec.Command(executable, "--remote-debugging-pipe", "--headless=new", "--enable-automation", "--no-first-run", "--no-default-browser-check", "--disable-background-networking", "--disable-extensions", "--disable-sync", "--user-data-dir="+profile, "about:blank")
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	if e = browserPipes(cmd, childRead, childWrite, parentRead, parentWrite); e != nil {
		closeFiles()
		return "", nil, e
	}
	if e = cmd.Start(); e != nil {
		closeFiles()
		return "", nil, errors.New("cannot start pipe browser")
	}
	childRead.Close()
	childWrite.Close()
	ctx, cancel := context.WithCancel(context.Background())
	p := &cdpProxy{ctx: ctx, cancel: cancel, pipe: chromedp.NewPipeConn(parentRead, parentWrite), pending: map[int64]cdpPending{}, sessions: map[target.SessionID]*cdpPeer{}, peers: map[*cdpPeer]bool{}}
	listener, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		cancel()
		closeFiles()
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return "", nil, e
	}
	token := make([]byte, 16)
	if _, e = rand.Read(token); e != nil {
		listener.Close()
		cancel()
		closeFiles()
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return "", nil, e
	}
	path := "/devtools/browser/" + hex.EncodeToString(token)
	server := &http.Server{ReadHeaderTimeout: 5 * time.Second, ErrorLog: log.New(io.Discard, "", 0), Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if r.Method != "GET" || r.URL.RawQuery != "" || subtle.ConstantTimeCompare([]byte(r.URL.EscapedPath()), []byte(path)) != 1 || ctx.Err() != nil {
			http.Error(w, "CDP capability required", http.StatusForbidden)
			return
		}
		p.serve(w, r)
	})}
	exited := make(chan struct{})
	var once sync.Once
	closeBrowser := func() {
		once.Do(func() {
			cancel()
			_ = server.Close()
			_ = p.pipe.Close()
			p.mu.Lock()
			for peer := range p.peers {
				peer.cancel()
				_ = peer.ws.CloseNow()
			}
			p.mu.Unlock()
			_ = cmd.Process.Kill()
		})
	}
	go func() { _ = cmd.Wait(); closeBrowser(); close(exited) }()
	go func() { _ = server.Serve(listener) }()
	go func() { p.read(); closeBrowser() }()
	closeAndWait := func() { closeBrowser(); <-exited }
	return "ws://" + listener.Addr().String() + path, closeAndWait, nil
}

func (p *cdpProxy) serve(w http.ResponseWriter, r *http.Request) {
	ws, e := websocket.Accept(w, r, nil)
	if e != nil {
		return
	}
	ws.SetReadLimit(16 << 20)
	ctx, cancel := context.WithCancel(p.ctx)
	peer := &cdpPeer{ctx: ctx, cancel: cancel, ws: ws, out: make(chan *cdproto.Message, 512)}
	defer func() { cancel(); _ = ws.CloseNow(); p.remove(peer) }()
	attached := make(chan *cdproto.Message, 1)
	p.mu.Lock()
	p.peers[peer] = true
	p.next++
	id := p.next
	p.pending[id] = cdpPending{peer: peer, attach: attached}
	p.mu.Unlock()
	if e = p.pipe.Write(ctx, &cdproto.Message{ID: id, Method: "Target.attachToBrowserTarget"}); e != nil {
		return
	}
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	select {
	case msg := <-attached:
		if msg.Error != nil || peer.root == "" {
			return
		}
	case <-ctx.Done():
		return
	case <-timer.C:
		return
	}
	go func() {
		for {
			select {
			case msg := <-peer.out:
				b, e := json.Marshal(msg)
				if e != nil || ws.Write(ctx, websocket.MessageText, b) != nil {
					cancel()
					_ = ws.CloseNow()
					return
				}
			case <-ctx.Done():
				return
			}
		}
	}()
	for {
		kind, b, e := ws.Read(ctx)
		if e != nil || kind != websocket.MessageText {
			return
		}
		var msg cdproto.Message
		if json.Unmarshal(b, &msg) != nil || msg.ID <= 0 || msg.Method == "" {
			return
		}
		p.mu.Lock()
		sid := msg.SessionID
		if sid == "" {
			msg.SessionID = peer.root
		} else if p.sessions[sid] != peer {
			p.mu.Unlock()
			return
		}
		if len(p.pending) >= 4096 {
			p.mu.Unlock()
			return
		}
		p.next++
		p.pending[p.next] = cdpPending{peer: peer, id: msg.ID, session: sid}
		msg.ID = p.next
		p.mu.Unlock()
		if p.pipe.Write(ctx, &msg) != nil {
			return
		}
	}
}

func (p *cdpProxy) remove(peer *cdpPeer) {
	p.mu.Lock()
	delete(p.peers, peer)
	for sid, owner := range p.sessions {
		if owner == peer {
			delete(p.sessions, sid)
		}
	}
	for id, call := range p.pending {
		if call.peer == peer {
			delete(p.pending, id)
		}
	}
	p.next++
	id := p.next
	p.mu.Unlock()
	if peer.root != "" && p.ctx.Err() == nil {
		params, _ := json.Marshal(map[string]any{"sessionId": peer.root})
		_ = p.pipe.Write(p.ctx, &cdproto.Message{ID: id, Method: "Target.detachFromTarget", Params: params})
	}
}

func (p *cdpProxy) read() {
	for {
		msg := new(cdproto.Message)
		if p.pipe.Read(p.ctx, msg) != nil {
			return
		}
		p.mu.Lock()
		var peer *cdpPeer
		if msg.ID != 0 {
			call, ok := p.pending[msg.ID]
			delete(p.pending, msg.ID)
			if !ok || call.peer.ctx.Err() != nil {
				p.mu.Unlock()
				continue
			}
			peer = call.peer
			var result struct {
				SessionID target.SessionID `json:"sessionId"`
			}
			_ = json.Unmarshal(msg.Result, &result)
			if result.SessionID != "" {
				p.sessions[result.SessionID] = peer
			}
			if call.attach != nil {
				peer.root = result.SessionID
				call.attach <- msg
				p.mu.Unlock()
				continue
			}
			msg.ID = call.id
			msg.SessionID = call.session
		} else {
			peer = p.sessions[msg.SessionID]
			if peer == nil || peer.ctx.Err() != nil {
				p.mu.Unlock()
				continue
			}
			var event struct {
				SessionID target.SessionID `json:"sessionId"`
			}
			_ = json.Unmarshal(msg.Params, &event)
			if msg.Method == "Target.attachedToTarget" && event.SessionID != "" {
				p.sessions[event.SessionID] = peer
			}
			if msg.Method == "Target.detachedFromTarget" {
				delete(p.sessions, event.SessionID)
			}
			if msg.SessionID == peer.root {
				msg.SessionID = ""
			}
		}
		select {
		case peer.out <- msg:
		default:
			peer.cancel()
			_ = peer.ws.CloseNow()
		}
		p.mu.Unlock()
	}
}
