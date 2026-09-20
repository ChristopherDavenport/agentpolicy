package agentpolicy

import (
	"encoding/json"
	"strings"
)

// Matcher decides whether a specifier matches one subject's arguments.
// A product registers one per tool that takes specifiers; a rule with
// a specifier for a tool without a matcher is an error at [Build], not
// a silent non-match.
type Matcher func(spec string, args json.RawMessage) bool

// PrefixMatcher is the common case: the specifier is "<prefix>:*",
// matched as a prefix of one string field of the arguments, or any
// other value, matched exactly. A missing field, or one that is not a
// string, matches nothing.
func PrefixMatcher(field string) Matcher {
	return func(spec string, args json.RawMessage) bool {
		val, ok := stringField(args, field)
		if !ok {
			return false
		}
		if prefix, ok := strings.CutSuffix(spec, ":*"); ok {
			return strings.HasPrefix(val, prefix)
		}
		return val == spec
	}
}

// stringField returns one string member of a JSON object.
func stringField(args json.RawMessage, field string) (string, bool) {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(args, &m); err != nil {
		return "", false
	}
	raw, ok := m[field]
	if !ok {
		return "", false
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return "", false
	}
	return s, true
}

// Subject is one thing the policy is evaluated against. A call is one
// subject, its own arguments, unless the tool's [Subjects] splits it.
type Subject struct {
	// Args is the subject as the matchers see it.
	Args json.RawMessage
	// Tool, when set, evaluates the subject against another tool's
	// rules, as a shell redirect target is checked against the file
	// tool's rules. Empty means the tool that was called.
	Tool string
	// Text is what a prompt shows for this subject.
	Text string
}

// Subjects splits one call into its subjects, after normalisation. A
// shell tool splits a command on its operators and strips wrappers; a
// file tool resolves its path; most tools are one subject, the call
// itself, and register no splitter. The splitter is the product's; the
// root package holds no shell parser. An error fails closed: the call
// is blocked with the error as the reason.
type Subjects func(args json.RawMessage) ([]Subject, error)

// ToolMatcher is what a product registers for a tool: how a specifier
// is matched and, when one call is several subjects, how it splits.
type ToolMatcher struct {
	Match Matcher
	// Subjects is nil for a tool that is one subject per call.
	Subjects Subjects
}
