package daemon

import (
	"encoding/json"
	"net/http"
)

func (s *Server) handleUpstreamPolicy(w http.ResponseWriter, r *http.Request, ac adminCtx) {
	body, err := readBody(r)
	if err != nil {
		s.fail(w, 400, "bad JSON")
		return
	}
	name, tool, risk := rawString(body, "name"), rawString(body, "tool"), rawString(body, "risk")
	if name == "" || tool == "" || len(name) > 100 || len(tool) > 100 {
		s.fail(w, 400, "name and exact raw tool required")
		return
	}
	if err := s.stepUp(ac, "upstream-policy:"+name+":"+tool+":"+risk, body, true); err != nil {
		s.fail(w, 403, err.Error())
		return
	}
	if err := s.up.SetToolRisk(r.Context(), name, tool, risk); err != nil {
		s.fail(w, 400, s.red.String(err.Error()))
		return
	}
	s.store.Audit("owner", "upstream.policy", "ok", 0, name+":"+tool+":"+risk)
	writeJSON(w, 200, map[string]any{"ok": true, "name": name, "tool": tool, "risk": risk})
}

func (s *Server) handleNotionPageEdits(w http.ResponseWriter, r *http.Request, ac adminCtx) {
	body, err := readBody(r)
	if err != nil {
		s.fail(w, 400, "bad JSON")
		return
	}
	name, tool := rawString(body, "name"), rawString(body, "tool")
	var enabled bool
	if name == "" || tool == "" || len(name) > 100 || len(tool) > 100 || json.Unmarshal(body["enabled"], &enabled) != nil {
		s.fail(w, 400, "name, tool and enabled are required")
		return
	}
	if err := s.stepUp(ac, "notion-page-edits:"+name+":"+tool, body, true); err != nil {
		s.fail(w, 403, err.Error())
		return
	}
	if err := s.up.SetNotionPageEdits(r.Context(), name, tool, enabled); err != nil {
		s.fail(w, 400, s.red.String(err.Error()))
		return
	}
	s.store.Audit("owner", "upstream.notion-page-edits", "ok", 0, name+":"+tool)
	writeJSON(w, 200, map[string]any{"ok": true, "name": name, "tool": tool, "enabled": enabled})
}
