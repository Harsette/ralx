// Package actions defines RalX's named actions: the only things an agent can
// ask RalX to do. Each action has a typed parameter list, a risk class, and
// either a fixed CLI argv template or a native Go implementation.
package actions

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"path"
	"regexp"
	"sort"
	"strings"
)

type Risk string

const (
	Read  Risk = "read"  // runs immediately
	Write Risk = "write" // runs immediately, private side effects only (logged)
	Gated Risk = "gated" // deploys, deletes, pays, emails or posts: held for the owner's yes
)

type Param struct {
	Name        string   `json:"name" yaml:"name"`
	Type        string   `json:"type" yaml:"type"` // string | integer | boolean | array
	Description string   `json:"description,omitempty" yaml:"description"`
	Required    bool     `json:"required,omitempty" yaml:"required"`
	Default     any      `json:"default,omitempty" yaml:"default"`
	Pattern     string   `json:"pattern,omitempty" yaml:"pattern"`
	Enum        []string `json:"enum,omitempty" yaml:"enum"`
	Min         *float64 `json:"min,omitempty" yaml:"min"`
	Max         *float64 `json:"max,omitempty" yaml:"max"`
	MaxLen      int      `json:"max_len,omitempty" yaml:"max_len"`
	// AllowLeadingDash permits values starting with "-". Off by default so a
	// value can never be smuggled in as a CLI flag.
	AllowLeadingDash bool `json:"-" yaml:"allow_leading_dash"`

	re *regexp.Regexp
}

// CLISpec runs a real CLI with a fixed argv. Each element is either a literal,
// a whole-element placeholder "{param}", or an optional group that is dropped
// when any placeholder inside it is empty/false.
type CLISpec struct {
	Tool    string            `yaml:"tool"`
	Argv    []ArgvElem        `yaml:"argv"`
	Env     map[string]string `yaml:"env"`    // NAME: "secret:<credential>.<field>" or a literal
	Output  string            `yaml:"output"` // json | text
	Timeout int               `yaml:"timeout_seconds"`
}

type ArgvElem struct {
	Lit string   `yaml:"-"`
	Opt []string `yaml:"opt"`
	Map *ArgMap  `yaml:"map"`
}

// ArgMap turns an enum parameter into a fixed literal, e.g. visibility=public
// becomes "--public". Values not in the map are rejected.
type ArgMap struct {
	Param  string            `yaml:"param"`
	Values map[string]string `yaml:"values"`
}

func (e *ArgvElem) UnmarshalYAML(unmarshal func(any) error) error {
	var s string
	if err := unmarshal(&s); err == nil {
		e.Lit = s
		return nil
	}
	var m struct {
		Opt []string `yaml:"opt"`
		Map *ArgMap  `yaml:"map"`
	}
	if err := unmarshal(&m); err != nil {
		return err
	}
	e.Opt, e.Map = m.Opt, m.Map
	return nil
}

// Env is what a native action gets to work with. It is implemented by the
// daemon and deliberately has no method that hands a secret to the caller of
// the action; native code uses secrets internally and returns results only.
type Env interface {
	Secret(credential string) (map[string]string, error)
	Redact(s string) string
	AgentName() string
	// StagedFile resolves a file the same agent uploaded to RalX's private
	// staging area (never an arbitrary path on disk), with its identity so an
	// approval can be bound to the exact bytes.
	StagedFile(uploadID string) (path, name, mimeType, sha256 string, size int64, err error)
}

type NativeFunc func(ctx context.Context, env Env, args map[string]any) (any, error)

type Action struct {
	Name        string   `json:"name" yaml:"name"`
	Description string   `json:"description" yaml:"description"`
	Risk        Risk     `json:"risk" yaml:"risk"`
	GateReason  string   `json:"gate_reason,omitempty" yaml:"gate_reason"` // deletes | emails | posts | deploys | pays | publishes
	Params      []Param  `json:"params" yaml:"params"`
	Requires    []string `json:"requires,omitempty" yaml:"requires"` // credential names needed
	// GateIf makes a write action gated only for certain argument values,
	// e.g. {"visibility": ["public"]}.
	GateIf map[string][]string `json:"gate_if,omitempty" yaml:"gate_if"`
	// GateFunc, for native actions, decides gating from the arguments; it
	// should return true unless the call is provably private.
	GateFunc func(args map[string]any) bool `json:"-" yaml:"-"`
	// SummaryTemplate renders a human line for approvals, e.g. "Delete repo {repo}".
	SummaryTemplate string `json:"-" yaml:"summary"`

	CLI    *CLISpec   `json:"-" yaml:"cli"`
	Native NativeFunc `json:"-" yaml:"-"`
	// Passthrough actions (tools of an upstream MCP server) keep the
	// upstream's own JSON schema; RalX only bounds the size of arguments.
	Passthrough bool           `json:"-" yaml:"-"`
	RawSchema   map[string]any `json:"-" yaml:"-"`
	// DefDigest identifies an upstream tool's definition (provider, raw name and
	// schema). An approval records it so a reload that changes the definition
	// under the same normalized name can't execute the approved one (Astra R7).
	DefDigest string `json:"-" yaml:"-"`
	// Stream marks actions that move file bytes between the agent's machine
	// and RalX (handled by the client, not callable as a plain action).
	Stream bool `json:"stream,omitempty" yaml:"-"`
}

func (a *Action) Compile() error {
	if a.Name == "" || !regexp.MustCompile(`^[a-z0-9]+(\.[a-z0-9_]+)+$`).MatchString(a.Name) {
		return fmt.Errorf("action name %q must look like tool.verb", a.Name)
	}
	switch a.Risk {
	case Read, Write, Gated:
	default:
		return fmt.Errorf("%s: unknown risk %q", a.Name, a.Risk)
	}
	if a.Risk == Gated && a.GateReason == "" {
		return fmt.Errorf("%s: gated actions need a gate_reason", a.Name)
	}
	seen := map[string]bool{}
	for i := range a.Params {
		p := &a.Params[i]
		if seen[p.Name] {
			return fmt.Errorf("%s: duplicate param %s", a.Name, p.Name)
		}
		seen[p.Name] = true
		switch p.Type {
		case "string", "integer", "boolean", "array":
		case "":
			p.Type = "string"
		default:
			return fmt.Errorf("%s.%s: unknown type %q", a.Name, p.Name, p.Type)
		}
		if p.Pattern != "" {
			re, err := regexp.Compile("^(?:" + p.Pattern + ")$")
			if err != nil {
				return fmt.Errorf("%s.%s: bad pattern: %w", a.Name, p.Name, err)
			}
			p.re = re
		}
	}
	if (a.CLI == nil) == (a.Native == nil) && !a.Stream {
		return fmt.Errorf("%s: needs exactly one of cli or native", a.Name)
	}
	if a.CLI != nil {
		if a.CLI.Tool == "" {
			return fmt.Errorf("%s: cli.tool required", a.Name)
		}
		for _, el := range a.CLI.Argv {
			if el.Map != nil {
				if !seen[el.Map.Param] || len(el.Map.Values) == 0 {
					return fmt.Errorf("%s: argv map references unknown param %q", a.Name, el.Map.Param)
				}
				continue
			}
			for _, s := range append([]string{el.Lit}, el.Opt...) {
				for _, ph := range placeholders(s) {
					if !seen[ph] {
						return fmt.Errorf("%s: argv references unknown param %q", a.Name, ph)
					}
				}
				if len(placeholders(s)) > 0 && !wholePlaceholder(s) {
					return fmt.Errorf("%s: placeholder must be a whole argv element (got %q)", a.Name, s)
				}
			}
		}
	}
	return nil
}

var phRe = regexp.MustCompile(`\{([a-z_][a-z0-9_]*)\}`)

func placeholders(s string) []string {
	var out []string
	for _, m := range phRe.FindAllStringSubmatch(s, -1) {
		out = append(out, m[1])
	}
	return out
}

func wholePlaceholder(s string) bool {
	m := phRe.FindStringSubmatchIndex(s)
	return m != nil && m[0] == 0 && m[1] == len(s)
}

// Validate checks agent-supplied arguments against the schema, fills defaults
// and returns a clean map. Unknown arguments are rejected.
func (a *Action) Validate(raw map[string]any) (map[string]any, error) {
	if a.Passthrough {
		b, _ := json.Marshal(raw)
		if len(b) > 1<<20 {
			return nil, errors.New("arguments larger than 1 MB")
		}
		return raw, nil
	}
	out := map[string]any{}
	known := map[string]*Param{}
	for i := range a.Params {
		known[a.Params[i].Name] = &a.Params[i]
	}
	for k := range raw {
		if known[k] == nil {
			return nil, fmt.Errorf("unknown argument %q", k)
		}
	}
	for _, p := range a.Params {
		v, ok := raw[p.Name]
		if !ok || v == nil {
			if p.Required {
				return nil, fmt.Errorf("missing required argument %q", p.Name)
			}
			if p.Default != nil {
				out[p.Name] = p.Default
			}
			continue
		}
		cv, err := p.check(v)
		if err != nil {
			return nil, fmt.Errorf("argument %q: %w", p.Name, err)
		}
		out[p.Name] = cv
	}
	return out, nil
}

func (p *Param) check(v any) (any, error) {
	switch p.Type {
	case "string":
		s, ok := v.(string)
		if !ok {
			return nil, errors.New("must be a string")
		}
		return s, p.checkString(s)
	case "integer":
		var f float64
		switch n := v.(type) {
		case float64:
			f = n
		case int:
			f = float64(n)
		case int64:
			f = float64(n)
		case json.Number:
			x, err := n.Float64()
			if err != nil {
				return nil, errors.New("must be an integer")
			}
			f = x
		default:
			return nil, errors.New("must be an integer")
		}
		if f != math.Trunc(f) {
			return nil, errors.New("must be an integer")
		}
		if p.Min != nil && f < *p.Min {
			return nil, fmt.Errorf("must be >= %v", *p.Min)
		}
		if p.Max != nil && f > *p.Max {
			return nil, fmt.Errorf("must be <= %v", *p.Max)
		}
		return int64(f), nil
	case "boolean":
		b, ok := v.(bool)
		if !ok {
			return nil, errors.New("must be true or false")
		}
		return b, nil
	case "array":
		arr, ok := v.([]any)
		if !ok {
			if ss, ok2 := v.([]string); ok2 {
				for _, s := range ss {
					arr = append(arr, s)
				}
			} else {
				return nil, errors.New("must be an array of strings")
			}
		}
		if len(arr) > 50 {
			return nil, errors.New("too many items")
		}
		var out []string
		for _, it := range arr {
			s, ok := it.(string)
			if !ok {
				return nil, errors.New("items must be strings")
			}
			if err := p.checkString(s); err != nil {
				return nil, err
			}
			out = append(out, s)
		}
		return out, nil
	}
	return nil, errors.New("unsupported type")
}

func (p *Param) checkString(s string) error {
	maxLen := p.MaxLen
	if maxLen == 0 {
		maxLen = 4096
	}
	if len(s) > maxLen {
		return fmt.Errorf("longer than %d characters", maxLen)
	}
	if strings.ContainsRune(s, 0) {
		return errors.New("contains a NUL byte")
	}
	if !p.AllowLeadingDash && strings.HasPrefix(s, "-") {
		return errors.New("may not start with '-'")
	}
	if len(p.Enum) > 0 {
		ok := false
		for _, e := range p.Enum {
			if s == e {
				ok = true
			}
		}
		if !ok {
			return fmt.Errorf("must be one of %s", strings.Join(p.Enum, ", "))
		}
	}
	if p.re != nil && !p.re.MatchString(s) {
		return fmt.Errorf("does not match %s", p.Pattern)
	}
	return nil
}

// IsGated reports whether this call (with these validated args) must wait for
// the owner's approval.
func (a *Action) IsGated(args map[string]any) bool {
	if a.Risk == Gated {
		return true
	}
	if a.GateFunc != nil && a.GateFunc(args) {
		return true
	}
	for k, vals := range a.GateIf {
		v := fmt.Sprint(args[k])
		for _, g := range vals {
			if v == g {
				return true
			}
		}
	}
	return false
}

// Summary renders the human-readable line shown on an approval card.
func (a *Action) Summary(args map[string]any) string {
	t := a.SummaryTemplate
	if t == "" {
		keys := make([]string, 0, len(args))
		for k := range args {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		var parts []string
		for _, k := range keys {
			parts = append(parts, fmt.Sprintf("%s=%v", k, args[k]))
		}
		return a.Name + " " + strings.Join(parts, " ")
	}
	return phRe.ReplaceAllStringFunc(t, func(m string) string {
		v, ok := args[m[1:len(m)-1]]
		if !ok {
			return ""
		}
		if list, ok := v.([]string); ok {
			return strings.Join(list, ", ")
		}
		return fmt.Sprint(v)
	})
}

// BuildArgv turns validated args into the concrete argv for a CLI action.
func (a *Action) BuildArgv(args map[string]any) ([]string, error) {
	if a.CLI == nil {
		return nil, errors.New("not a CLI action")
	}
	var argv []string
	render := func(s string) (vals []string, empty bool) {
		if !wholePlaceholder(s) {
			return []string{s}, false
		}
		v, ok := args[s[1:len(s)-1]]
		if !ok || v == nil {
			return nil, true
		}
		switch x := v.(type) {
		case string:
			return []string{x}, x == ""
		case bool:
			if !x {
				return nil, true
			}
			return nil, false // a true boolean contributes only the literal flags around it
		case int64:
			return []string{fmt.Sprint(x)}, false
		case []string:
			return x, len(x) == 0
		}
		return []string{fmt.Sprint(v)}, false
	}
	for _, el := range a.CLI.Argv {
		if el.Map != nil {
			v := fmt.Sprint(args[el.Map.Param])
			lit, ok := el.Map.Values[v]
			if !ok {
				return nil, fmt.Errorf("argument %q: %q is not allowed", el.Map.Param, v)
			}
			argv = append(argv, lit)
			continue
		}
		if el.Opt == nil {
			vals, empty := render(el.Lit)
			if empty {
				return nil, fmt.Errorf("argv element %q has no value", el.Lit)
			}
			argv = append(argv, vals...)
			continue
		}
		var group []string
		drop := false
		for _, s := range el.Opt {
			vals, empty := render(s)
			if empty {
				drop = true
				break
			}
			group = append(group, vals...)
		}
		if !drop {
			argv = append(argv, group...)
		}
	}
	return argv, nil
}

// Allowed reports whether an action name passes an allow/deny glob policy.
func Allowed(name string, allow, deny []string) bool {
	for _, d := range deny {
		if ok, _ := path.Match(d, name); ok {
			return false
		}
	}
	if len(allow) == 0 {
		return true
	}
	for _, g := range allow {
		if ok, _ := path.Match(g, name); ok {
			return true
		}
	}
	return false
}

// JSONSchema renders the parameter list as a JSON Schema object for MCP.
func (a *Action) JSONSchema() map[string]any {
	if a.RawSchema != nil {
		return a.RawSchema
	}
	props := map[string]any{}
	var req []string
	for _, p := range a.Params {
		s := map[string]any{"type": p.Type}
		if p.Type == "array" {
			s["items"] = map[string]any{"type": "string"}
		}
		if p.Description != "" {
			s["description"] = p.Description
		}
		if len(p.Enum) > 0 {
			s["enum"] = p.Enum
		}
		if p.Default != nil {
			s["default"] = p.Default
		}
		if p.Min != nil {
			s["minimum"] = *p.Min
		}
		if p.Max != nil {
			s["maximum"] = *p.Max
		}
		props[p.Name] = s
		if p.Required {
			req = append(req, p.Name)
		}
	}
	out := map[string]any{"type": "object", "properties": props, "additionalProperties": false}
	if len(req) > 0 {
		out["required"] = req
	}
	return out
}
