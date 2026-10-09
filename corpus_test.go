package agentpolicy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"testing"

	"github.com/ChristopherDavenport/agenttool"
	"github.com/ChristopherDavenport/agentturn"
	"github.com/ChristopherDavenport/openresponses"
)

// The corpus in testdata/policy is RFC 0001's conformance corpus: the
// grammar, the reference matchers and the decisions, as JSON a second
// implementation runs. These tests are the reference binding's run of
// it, so the corpus is the test rather than a copy of one.

// load decodes one corpus file, refusing members the harness does not
// read, so a fixture that names a field nobody checks fails loudly.
func load(t *testing.T, name string, into any) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "policy", name))
	if err != nil {
		t.Fatal(err)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(into); err != nil {
		t.Fatalf("%s: %v", name, err)
	}
}

// grammarErrors is the text the reference gives each error kind.
var grammarErrors = map[string]string{
	"unbalanced_parentheses": "unbalanced parentheses",
	"missing_tool_name":      "missing tool name",
	"empty_specifier":        "empty specifier",
	"empty_carve_out":        "empty carve-out",
	"text_after_specifier":   "text after the specifier",
}

func TestCorpusGrammar(t *testing.T) {
	var corpus struct {
		Cases []struct {
			Name  string `json:"name"`
			Input string `json:"input"`
			Rules []struct {
				Tool string `json:"tool"`
				Spec string `json:"spec"`
			} `json:"rules"`
			Error *struct {
				Kind  string `json:"kind"`
				Token string `json:"token"`
			} `json:"error"`
		} `json:"cases"`
	}
	load(t, "grammar.json", &corpus)
	for _, tc := range corpus.Cases {
		got, err := ParseRules(tc.Input)
		if tc.Error != nil {
			text, ok := grammarErrors[tc.Error.Kind]
			if !ok {
				t.Fatalf("%s: unknown error kind %q", tc.Name, tc.Error.Kind)
			}
			want := fmt.Sprintf("agentpolicy: rule %q: %s", tc.Error.Token, text)
			if err == nil || err.Error() != want {
				t.Errorf("%s: ParseRules(%q) err = %v, want %q", tc.Name, tc.Input, err, want)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: ParseRules(%q): %v", tc.Name, tc.Input, err)
			continue
		}
		var want []Rule
		for _, r := range tc.Rules {
			want = append(want, Rule{Tool: r.Tool, Spec: r.Spec})
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s: ParseRules(%q) = %+v, want %+v", tc.Name, tc.Input, got, want)
		}
		// A rule's string form is the token it was parsed from.
		for i, r := range got {
			want := tc.Rules[i].Tool
			if tc.Rules[i].Spec != "" {
				want += "(" + tc.Rules[i].Spec + ")"
			}
			if s := r.String(); s != want {
				t.Errorf("%s: rule %d renders %q, want %q", tc.Name, i, s, want)
			}
		}
	}
}

// matcherOf builds a reference matcher by its corpus name.
func matcherOf(t *testing.T, name, field string) Matcher {
	t.Helper()
	switch name {
	case "prefix":
		return PrefixMatcher(field)
	case "glob":
		return GlobMatcher(field)
	case "":
		return nil
	}
	t.Fatalf("unknown matcher %q", name)
	return nil
}

func TestCorpusMatchers(t *testing.T) {
	var corpus struct {
		Cases []struct {
			Matcher string          `json:"matcher"`
			Spec    string          `json:"spec"`
			Args    json.RawMessage `json:"args"`
			Raw     *string         `json:"raw"`
			Match   bool            `json:"match"`
		} `json:"cases"`
	}
	load(t, "matchers.json", &corpus)
	for _, tc := range corpus.Cases {
		args := tc.Args
		if tc.Raw != nil {
			args = json.RawMessage(*tc.Raw)
		}
		m := matcherOf(t, tc.Matcher, "command")
		if got := m(tc.Spec, args); got != tc.Match {
			t.Errorf("%s(%q, %s) = %v, want %v", tc.Matcher, tc.Spec, args, got, tc.Match)
		}
	}
}

// corpusRules is a rule list written in the grammar.
type corpusRules string

func (s corpusRules) parse(t *testing.T, notes map[string]string) []Rule {
	t.Helper()
	out, err := ParseRules(string(s))
	if err != nil {
		t.Fatal(err)
	}
	for i := range out {
		out[i].Note = notes[out[i].String()]
	}
	return out
}

type corpusSource struct {
	Name    string            `json:"name"`
	Rank    int               `json:"rank"`
	Trusted bool              `json:"trusted"`
	Allow   corpusRules       `json:"allow"`
	Deny    corpusRules       `json:"deny"`
	Ask     corpusRules       `json:"ask"`
	Notes   map[string]string `json:"notes"`
}

func (s corpusSource) set(t *testing.T) RuleSet {
	return RuleSet{
		Source: Source{Name: s.Name, Rank: s.Rank, Trusted: s.Trusted},
		Allow:  s.Allow.parse(t, s.Notes),
		Deny:   s.Deny.parse(t, s.Notes),
		Ask:    s.Ask.parse(t, s.Notes),
	}
}

type corpusSubject struct {
	Args json.RawMessage `json:"args"`
	Text string          `json:"text"`
	Tool string          `json:"tool"`
}

type corpusCall struct {
	Tool          string           `json:"tool"`
	Args          json.RawMessage  `json:"args"`
	Confined      *string          `json:"confined"`
	Subjects      *[]corpusSubject `json:"subjects"`
	SubjectsError string           `json:"subjects_error"`
	Want          struct {
		Action   string `json:"action"`
		Held     bool   `json:"held"`
		Rule     string `json:"rule"`
		Source   string `json:"source"`
		Reason   string `json:"reason"`
		Subject  string `json:"subject"`
		Confined string `json:"confined"`
	} `json:"want"`
}

// args is the call's arguments as the model sent them, compacted, so
// the harness can find a call's fixture again from its arguments.
func (c corpusCall) args(t *testing.T) string {
	var b bytes.Buffer
	if err := json.Compact(&b, c.Args); err != nil {
		t.Fatal(err)
	}
	return b.String()
}

type corpusMatcher struct {
	Match string `json:"match"`
	Field string `json:"field"`
	Split bool   `json:"split"`
}

type decisionCase struct {
	Name     string                   `json:"name"`
	Matchers map[string]corpusMatcher `json:"matchers"`
	Aliases  map[string][]string      `json:"aliases"`
	Policy   struct {
		Sources []corpusSource `json:"sources"`
		Allow   corpusRules    `json:"allow"`
		Deny    corpusRules    `json:"deny"`
		Ask     corpusRules    `json:"ask"`
		Default string         `json:"default"`
	} `json:"policy"`
	BuildError string `json:"build_error"`
	Grants     []struct {
		Source  corpusSource `json:"source"`
		Allow   corpusRules  `json:"allow"`
		Deny    corpusRules  `json:"deny"`
		Ask     corpusRules  `json:"ask"`
		Granted []string     `json:"granted"`
		Refused []struct {
			Rule   string `json:"rule"`
			Reason string `json:"reason"`
		} `json:"refused"`
	} `json:"grants"`
	Calls []corpusCall `json:"calls"`
	Batch []corpusCall `json:"batch"`
	Offer *struct {
		Tools []string `json:"tools"`
		Want  []string `json:"want"`
	} `json:"offer"`
}

// buildErrors is the sentinel each build error kind is in the
// reference.
var buildErrors = map[string]error{
	"no_default": ErrNoDefault,
	"no_matcher": ErrNoMatcher,
	"tool_glob":  ErrToolGlob,
	// The reference has no sentinel for an invalid rule; any error
	// that is none of the others is one.
	"invalid_rule": nil,
}

var corpusActions = map[string]agentturn.ToolAction{
	"allow": agentturn.Allow,
	"block": agentturn.Block,
	"defer": agentturn.Defer,
}

var corpusDefaults = map[string]Default{
	"":      {},
	"allow": Allow(),
	"deny":  Deny(),
	"ask":   Ask(),
}

func TestCorpusDecisions(t *testing.T) {
	var corpus struct {
		Matchers map[string]corpusMatcher `json:"matchers"`
		Cases    []decisionCase           `json:"cases"`
	}
	load(t, "decisions.json", &corpus)
	for _, tc := range corpus.Cases {
		t.Run(tc.Name, func(t *testing.T) {
			runDecisionCase(t, corpus.Matchers, tc)
		})
	}
}

func runDecisionCase(t *testing.T, defaults map[string]corpusMatcher, tc decisionCase) {
	ctx := context.Background()
	all := append(append([]corpusCall(nil), tc.Calls...), tc.Batch...)

	// The splitter and the confinement are the product's; the corpus
	// writes out what they answer for each call, found by its
	// arguments.
	type answer struct {
		subjects *[]corpusSubject
		err      string
		confined *string
	}
	answers := map[string]answer{}
	for _, c := range all {
		key := c.Tool + "\x00" + c.args(t)
		if _, dup := answers[key]; dup {
			t.Fatalf("two calls of %s with %s: a case's calls need distinct arguments", c.Tool, c.args(t))
		}
		answers[key] = answer{c.Subjects, c.SubjectsError, c.Confined}
	}

	specs := tc.Matchers
	if specs == nil {
		specs = defaults
	}
	matchers := map[string]ToolMatcher{}
	for name, m := range specs {
		tm := ToolMatcher{Match: matcherOf(t, m.Match, m.Field)}
		if m.Split {
			tm.Subjects = func(_ context.Context, args json.RawMessage) ([]Subject, error) {
				a := answers[name+"\x00"+string(args)]
				if a.err != "" {
					return nil, errors.New(a.err)
				}
				if a.subjects == nil {
					return []Subject{{Args: args}}, nil
				}
				out := []Subject{}
				for _, s := range *a.subjects {
					out = append(out, Subject{Args: s.Args, Text: s.Text, Tool: s.Tool})
				}
				return out, nil
			}
		}
		matchers[name] = tm
	}

	tools := map[string]agenttool.Tool{}
	toolOf := func(name string) agenttool.Tool {
		if tool, ok := tools[name]; ok {
			return tool
		}
		run := func(context.Context, struct{}) (string, error) { return "", nil }
		tool := agenttool.New(name, name, run, agenttool.WithConfined(func(_ context.Context, args json.RawMessage) (bool, string) {
			a := answers[name+"\x00"+string(args)]
			if a.confined == nil {
				return false, ""
			}
			return true, *a.confined
		}))
		tools[name] = tool
		return tool
	}
	for _, c := range all {
		toolOf(c.Tool)
	}

	sets := make([]RuleSet, 0, len(tc.Policy.Sources))
	for _, s := range tc.Policy.Sources {
		sets = append(sets, s.set(t))
	}
	p, err := Merge(sets...)
	if err != nil {
		t.Fatal(err)
	}
	p.Allow = append(p.Allow, tc.Policy.Allow.parse(t, nil)...)
	p.Deny = append(p.Deny, tc.Policy.Deny.parse(t, nil)...)
	p.Ask = append(p.Ask, tc.Policy.Ask.parse(t, nil)...)
	def, ok := corpusDefaults[tc.Policy.Default]
	if !ok {
		t.Fatalf("unknown default %q", tc.Policy.Default)
	}
	p.Default = def

	var last Verdict
	opts := []Option{
		WithObserver(func(_ context.Context, v Verdict) { last = v }),
		WithTools(func(name string) (agenttool.Tool, bool) {
			tool, ok := tools[name]
			return tool, ok
		}),
	}
	if tc.Aliases != nil {
		opts = append(opts, WithAliases(tc.Aliases))
	}
	e, err := Build(p, matchers, opts...)
	if tc.BuildError != "" {
		want, ok := buildErrors[tc.BuildError]
		if !ok {
			t.Fatalf("unknown build error %q", tc.BuildError)
		}
		if want == nil {
			invalid := err != nil
			for _, other := range buildErrors {
				if other != nil && errors.Is(err, other) {
					invalid = false
				}
			}
			if !invalid {
				t.Fatalf("Build err = %v, want invalid_rule", err)
			}
			return
		}
		if !errors.Is(err, want) {
			t.Fatalf("Build err = %v, want %v", err, want)
		}
		return
	}
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	for _, g := range tc.Grants {
		set := g.Source.set(t)
		set.Allow, set.Deny, set.Ask = g.Allow.parse(t, nil), g.Deny.parse(t, nil), g.Ask.parse(t, nil)
		granted, refused := e.GrantSet(ctx, set)
		var gotGranted []string
		for _, r := range granted {
			gotGranted = append(gotGranted, r.String())
		}
		if !slices.Equal(gotGranted, g.Granted) {
			t.Errorf("GrantSet(%s) granted %q, want %q", set.Source.Name, gotGranted, g.Granted)
		}
		var gotRefused, wantRefused []string
		for _, r := range refused {
			gotRefused = append(gotRefused, r.Rule.String()+" | "+r.Reason)
		}
		for _, r := range g.Refused {
			wantRefused = append(wantRefused, r.Rule+" | "+r.Reason)
		}
		if !slices.Equal(gotRefused, wantRefused) {
			t.Errorf("GrantSet(%s) refused\n%q\nwant\n%q", set.Source.Name, gotRefused, wantRefused)
		}
	}

	// Each of calls is a batch of its own; batch is one batch.
	decide := func(batch []corpusCall, turn int) {
		fcs := make([]*openresponses.FunctionCall, len(batch))
		for i, c := range batch {
			fcs[i] = &openresponses.FunctionCall{CallID: fmt.Sprintf("call_%d", i+1), Name: c.Tool, Arguments: c.args(t)}
		}
		for i, c := range batch {
			info := agentturn.ToolCallInfo{RunID: "run_1", Turn: turn, Call: fcs[i], Tool: toolOf(c.Tool), Args: json.RawMessage(fcs[i].Arguments), Batch: fcs, Index: i}
			d, err := e.Decide(ctx, info)
			v := last
			if err != nil {
				t.Fatalf("%s %s: %v", c.Tool, fcs[i].Arguments, err)
			}
			w := c.Want
			action, ok := corpusActions[w.Action]
			if !ok {
				t.Fatalf("unknown action %q", w.Action)
			}
			rule, source := "", ""
			if v.Rule != nil {
				rule, source = v.Rule.String(), v.Rule.Source.Name
			}
			got := fmt.Sprintf("action=%v held=%v rule=%q source=%q reason=%q subject=%q confined=%q",
				v.Action, v.Held, rule, source, v.Reason, v.Subject, v.Confined)
			want := fmt.Sprintf("action=%v held=%v rule=%q source=%q reason=%q subject=%q confined=%q",
				action, w.Held, w.Rule, w.Source, w.Reason, w.Subject, w.Confined)
			if got != want {
				t.Errorf("%s %s:\n got %s\nwant %s", c.Tool, fcs[i].Arguments, got, want)
			}
			if d.Action != v.Action || d.Reason != v.Reason || d.By != ByPolicy {
				t.Errorf("%s %s: decision %+v does not carry the verdict %+v", c.Tool, fcs[i].Arguments, d, v)
			}
			if v.RunID != "run_1" || v.Turn != turn || v.CallID != fcs[i].CallID || v.Tool != c.Tool || v.By != ByPolicy {
				t.Errorf("%s %s: verdict names %q %d %q %q %q", c.Tool, fcs[i].Arguments, v.RunID, v.Turn, v.CallID, v.Tool, v.By)
			}
			// The same policy and the same call in the same batch give
			// the same decision.
			if again, err := e.Decide(ctx, info); err != nil || !reflect.DeepEqual(again, d) {
				t.Errorf("%s %s: decided again as %+v, %v; first %+v", c.Tool, fcs[i].Arguments, again, err, d)
			}
		}
	}
	for i, c := range tc.Calls {
		decide([]corpusCall{c}, i+1)
	}
	if len(tc.Batch) > 0 {
		decide(tc.Batch, len(tc.Calls)+1)
	}

	if tc.Offer != nil {
		list := make([]agenttool.Tool, 0, len(tc.Offer.Tools))
		for _, name := range tc.Offer.Tools {
			list = append(list, toolOf(name))
		}
		var got []string
		for _, tool := range e.Filter(list) {
			got = append(got, tool.Name())
		}
		if !slices.Equal(got, tc.Offer.Want) {
			t.Errorf("Filter(%q) = %q, want %q", tc.Offer.Tools, got, tc.Offer.Want)
		}
	}
}
