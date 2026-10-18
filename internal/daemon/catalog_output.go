package daemon

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
)

// Select only the generated list response, never an arbitrary tools/call result.
func catalogRequest(r *http.Request) (rest bool, id json.RawMessage) {
	if r.Method == "GET" && r.URL.Path == "/v1/actions" {
		return true, nil
	}
	if r.Method != "POST" || r.URL.Path != "/mcp" || r.Body == nil {
		return false, nil
	}
	original := r.Body
	b, err := io.ReadAll(io.LimitReader(original, (64<<10)+1))
	r.Body = &catalogRequestBody{Reader: io.MultiReader(bytes.NewReader(b), original), Closer: original}
	if err != nil || len(b) > 64<<10 {
		return false, nil
	}
	var request struct {
		Version string          `json:"jsonrpc"`
		Method  string          `json:"method"`
		ID      json.RawMessage `json:"id"`
	}
	if json.Unmarshal(b, &request) != nil || request.Version != "2.0" || request.Method != "tools/list" || len(request.ID) == 0 || bytes.Equal(request.ID, []byte("null")) {
		return false, nil
	}
	return false, request.ID
}

type catalogRequestBody struct {
	io.Reader
	io.Closer
}

func (w *agentWriter) catalogResponse(b []byte) bool {
	if w.code != http.StatusOK {
		return false
	}
	var response map[string]json.RawMessage
	if json.Unmarshal(b, &response) != nil {
		return false
	}
	if w.catalogREST {
		var actions []json.RawMessage
		return len(response) == 1 && json.Unmarshal(response["actions"], &actions) == nil && actions != nil
	}
	if len(w.catalogID) == 0 || len(response) != 3 || !bytes.Equal(bytes.TrimSpace(response["id"]), bytes.TrimSpace(w.catalogID)) || string(response["jsonrpc"]) != `"2.0"` {
		return false
	}
	var result map[string]json.RawMessage
	if json.Unmarshal(response["result"], &result) != nil {
		return false
	}
	for key := range result {
		if key != "tools" && key != "nextCursor" && key != "ttlMs" && key != "cacheScope" {
			return false
		}
	}
	var tools []json.RawMessage
	return json.Unmarshal(result["tools"], &tools) == nil && tools != nil
}

func (s *Server) agentCatalogScrub(b []byte) ([]byte, bool) {
	if s.red.ShortLiteral(string(b)) {
		return nil, true
	}
	clean := s.red.Bytes(b)
	if s.red.DeepContainsCatalogSecret(string(clean)) {
		return nil, true
	}
	return clean, false
}

func (s *Server) writeJSONAgentCatalog(w http.ResponseWriter, v any) {
	b, err := json.Marshal(v)
	if err != nil {
		s.fail(w, 500, "catalog encoding error")
		return
	}
	clean, held := s.agentCatalogScrub(b)
	if held {
		s.fail(w, 503, "catalog withheld - credential or scan limit")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(clean)
}
