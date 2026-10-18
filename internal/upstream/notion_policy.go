package upstream

import (
	"context"
	"errors"
	"net/url"
)

func notionPageTool(sc serverConf, tool string) bool {
	u, err := url.Parse(sc.URL)
	return err == nil && u.Scheme == "https" && u.Host == "mcp.notion.com" &&
		u.Path == "/mcp" && u.User == nil && u.RawQuery == "" && u.Fragment == "" &&
		(tool == "notion-update-page" || tool == "notion_update_page")
}

// Only explicitly reviewed property updates and inserts run under this rule.
// Content replacement, deletion flags, missing commands and extra arguments
// stay held. Provider annotations cannot grant this rule.
func notionPageEditGated(args map[string]any) bool {
	id, ok := args["page_id"].(string)
	if !ok || id == "" {
		return true
	}
	command, _ := args["command"].(string)
	allowed := map[string]bool{"page_id": true, "command": true}
	switch command {
	case "update_properties":
		properties, ok := args["properties"].(map[string]any)
		if !ok || len(properties) == 0 {
			return true
		}
		allowed["properties"] = true
	case "insert_content":
		text, ok := args["content"].(string)
		if !ok || text == "" {
			return true
		}
		allowed["content"], allowed["position"] = true, true
		if position, exists := args["position"]; exists {
			p, ok := position.(map[string]any)
			if !ok || len(p) != 1 || (p["type"] != "start" && p["type"] != "end") {
				return true
			}
		}
	default:
		return true
	}
	for k := range args {
		if !allowed[k] {
			return true
		}
	}
	return false
}

// SetNotionPageEdits preserves other reviewed tools and the account identity.
// The caller must authorize this through the local admin interface.
func (m *Manager) SetNotionPageEdits(ctx context.Context, name, tool string, enabled bool) error {
	risk := "deletes"
	if enabled {
		risk = "notion-page-edits"
	}
	return m.SetToolRisk(ctx, name, tool, risk)
}

// SetToolRisk is an owner-reviewed rule for one exact raw tool. It does not
// derive permission from an upstream name, description or annotation.
func (m *Manager) SetToolRisk(ctx context.Context, name, tool, risk string) error {
	switch risk {
	case "read", "write", "deletes", "posts", "emails", "deploys", "pays", "publishes", "notion-page-edits":
	default:
		return errors.New("unknown tool risk")
	}
	if reNeverLower.MatchString(tool) && (risk == "read" || risk == "write") {
		return errors.New("arbitrary-action tools cannot be lowered")
	}
	c, err := m.Store.GetCredential(credPrefix + name)
	if err != nil {
		return err
	}
	if c.Kind != "mcp_server" || (risk == "notion-page-edits" && !notionPageTool(confOf(c), tool)) {
		return errors.New("page edits require the official Notion MCP update-page tool")
	}
	// Confirm that the exact named tool exists before granting an exception.
	if _, ok := m.Reg.Get(actionName(confOf(c).Prefix, tool)); !ok {
		return errors.New("that tool is not in the connected catalog")
	}
	m.mu.Lock()
	entry := m.sessions[name]
	m.mu.Unlock()
	if entry == nil {
		return errors.New("upstream is not connected")
	}
	matched := false
	for t, err := range entry.sess.Tools(ctx, nil) {
		if err != nil {
			return err
		}
		if t.Name == tool {
			matched = true
			break
		}
	}
	if !matched {
		return errors.New("exact raw tool name not found")
	}
	ov := map[string]any{}
	if old, ok := c.Meta["risk_overrides"].(map[string]any); ok {
		for k, v := range old {
			ov[k] = v
		}
	}
	ov[tool] = risk
	if err := m.Store.UpdateMeta(c.Name, map[string]any{"risk_overrides": ov}); err != nil {
		return err
	}
	// No secret or account replacement: the existing generation stays intact.
	return m.Load(ctx, name)
}
