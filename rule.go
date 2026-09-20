package agentpolicy

import (
	"fmt"
	"strings"
)

// Rule is one token of the grammar: a tool name, or a name with a
// specifier in parentheses, "Bash(git:*)". It is the grammar of a
// skill's allowed-tools, so agentskill.ToolRule maps onto it field for
// field without either module importing the other. What a specifier
// means belongs to the tool's [Matcher]; the grammar knows one thing
// about it, that a specifier beginning with "!" is a carve-out.
type Rule struct {
	Tool string
	// Spec is the text inside the parentheses, "" for a bare name.
	Spec string
	// Source is where the rule came from. The zero Source is a rule
	// the product built itself.
	Source Source
}

// Source is where a set of rules came from: a settings file, a skill,
// the session. Name identifies the source and scopes a carve-out to
// the rules of the same source. Path and Hash let a session name the
// policy in force. Trusted false withholds the source's allow rules in
// [Merge], as a repository's settings wait for the user to trust the
// folder while its deny and ask rules apply at once; a Source built by
// hand is untrusted until it says otherwise. Rank orders sources by
// authority, higher first: a grant may answer an ask rule only from a
// source of equal or lower rank. Rank never affects precedence between
// lists; deny before ask before allow holds whatever the sources.
type Source struct {
	Name    string
	Path    string
	Hash    string
	Trusted bool
	Rank    int
}

// String returns the token as it is written: the name, or the name
// with the specifier in parentheses. The source is not rendered.
func (r Rule) String() string {
	if r.Spec == "" {
		return r.Tool
	}
	return r.Tool + "(" + r.Spec + ")"
}

// Bare reports whether the rule names a tool without a specifier, so
// it matches every call of the tool.
func (r Rule) Bare() bool { return r.Spec == "" }

// CarveOut returns the pattern of a carve-out, a specifier beginning
// with "!", and whether the rule is one. A carve-out never matches on
// its own; it cancels a match of another rule in the same list, for
// the same tool, from the same source, when its pattern matches the
// subject. The pattern is the tool's to interpret, as any specifier
// is.
func (r Rule) CarveOut() (pattern string, ok bool) {
	if strings.HasPrefix(r.Spec, "!") {
		return r.Spec[1:], true
	}
	return "", false
}

// ParseRules parses the grammar: tokens separated by whitespace, each
// a tool name or a name followed by a specifier in parentheses. Only
// whitespace outside parentheses separates tokens, so a specifier may
// contain spaces, "Bash(git status:*)", and parentheses inside a
// specifier are literal as long as they balance,
// "Edit(./Finance (2024)/**)". An empty string yields no rules and no
// error. The rules have no Source.
func ParseRules(s string) ([]Rule, error) {
	var rules []Rule
	depth, start := 0, -1
	flush := func(end int) error {
		if start < 0 {
			return nil
		}
		r, err := parseRule(s[start:end])
		if err != nil {
			return err
		}
		rules = append(rules, r)
		start = -1
		return nil
	}
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c == '(':
			depth++
		case c == ')':
			if depth == 0 {
				return nil, fmt.Errorf("agentpolicy: rule %q: unbalanced parentheses", tokenAt(s, start, i+1))
			}
			depth--
		case depth == 0 && isSpace(c):
			if err := flush(i); err != nil {
				return nil, err
			}
			continue
		}
		if start < 0 {
			start = i
		}
	}
	if depth != 0 {
		return nil, fmt.Errorf("agentpolicy: rule %q: unbalanced parentheses", s[start:])
	}
	if err := flush(len(s)); err != nil {
		return nil, err
	}
	return rules, nil
}

// tokenAt returns the token that contains position end, for an error.
func tokenAt(s string, start, end int) string {
	if start < 0 {
		start = end - 1
	}
	return s[start:end]
}

func isSpace(c byte) bool {
	switch c {
	case ' ', '\t', '\n', '\r', '\v', '\f':
		return true
	}
	return false
}

func parseRule(tok string) (Rule, error) {
	open := strings.IndexByte(tok, '(')
	if open < 0 {
		return Rule{Tool: tok}, nil
	}
	if open == 0 {
		return Rule{}, fmt.Errorf("agentpolicy: rule %q: missing tool name", tok)
	}
	if !strings.HasSuffix(tok, ")") {
		return Rule{}, fmt.Errorf("agentpolicy: rule %q: text after the specifier", tok)
	}
	spec := tok[open+1 : len(tok)-1]
	switch spec {
	case "":
		return Rule{}, fmt.Errorf("agentpolicy: rule %q: empty specifier", tok)
	case "!":
		return Rule{}, fmt.Errorf("agentpolicy: rule %q: empty carve-out", tok)
	}
	return Rule{Tool: tok[:open], Spec: spec}, nil
}
