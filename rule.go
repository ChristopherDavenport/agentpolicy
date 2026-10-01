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
	// Note says why the rule exists, "outbound network is proxied; use
	// fetch", in the words of whoever wrote it. It is not part of the
	// grammar: [ParseRules] leaves it empty, and a product's settings
	// parser fills it from a comment or a field beside the rule. When
	// set it follows the rule in the reason a verdict gives, which is
	// what the model reads for a denied call and what a prompt shows
	// for an asked one: "denied by bash(curl:*): outbound network is
	// proxied; use fetch". A note from a named source the user has not
	// trusted is left out of the reason, since the model would read a
	// repository's text in the harness's voice; it stays on
	// Verdict.Rule for the record and the front. Two rules that differ
	// only in their notes are the same rule to [Engine.GrantOver].
	Note string
}

// Source is where a set of rules came from: a settings file, a skill,
// the session. Name identifies the source, keys a scoped grant and
// names the file a product persists its own rules into. Path and Hash
// let a session name the policy in force. Trusted false withholds the
// source's allow rules in [Merge], as a repository's settings wait for
// the user to trust the folder while its deny and ask rules apply at
// once; a Source built by hand is untrusted until it says otherwise.
// Rank orders sources by authority, higher first: a grant may answer
// an ask rule only from a source of equal or lower rank, a carve-out
// cancels a rule only of a source it does not rank below, and a grant
// set's allow rules shadow only the ask rules it does not rank below.
// Rank never affects precedence between lists; deny before ask before
// allow holds whatever the sources.
type Source struct {
	Name    string
	Path    string
	Hash    string
	Trusted bool
	Rank    int
}

// String returns the token as it is written: the name, or the name
// with the specifier in parentheses. The source and the note are not
// rendered.
func (r Rule) String() string {
	if r.Spec == "" {
		return r.Tool
	}
	return r.Tool + "(" + r.Spec + ")"
}

// cite is the rule as a reason names it: the token, and the note after
// it when there is one and its source is the product's or trusted. An
// untrusted source's deny and ask rules apply, but what its note says
// is not the harness's to repeat to the model.
func (r Rule) cite() string {
	if r.Note == "" || !r.Source.Trusted && r.Source.Name != "" {
		return r.String()
	}
	return r.String() + ": " + r.Note
}

// same reports whether two rules are one rule: the tool, the specifier
// and the source, whatever their notes say.
func (r Rule) same(o Rule) bool {
	return r.Tool == o.Tool && r.Spec == o.Spec && r.Source == o.Source
}

// Bare reports whether the rule names a tool without a specifier, so
// it matches every call of the tool.
func (r Rule) Bare() bool { return r.Spec == "" }

// Glob reports whether the rule's tool name is a glob over tool names
// rather than one tool's own name, "mcp__*" for every tool of every
// MCP server. A glob is honoured in the deny and ask lists, where both
// references honour one, and [Build] refuses it in the allow list and
// refuses it with a specifier, since a glob names no matcher.
func (r Rule) Glob() bool { return strings.Contains(r.Tool, "*") }

// MatchesTool reports whether the rule's tool name names the tool: the
// same name, or a glob that matches it, where "*" stands for any run
// of characters at any position. Nothing folds case: the reference
// documents case sensitivity for almost nothing, so guessing here
// would replace a loud failure with a quiet one. It is the engine's
// own test, exported so a product that offers the model a tool list
// does not write a second one that can disagree.
func (r Rule) MatchesTool(tool string) bool {
	if !r.Glob() {
		return r.Tool == tool
	}
	return globMatch(r.Tool, tool)
}

// globMatch matches a pattern whose "*" stands for any run of
// characters against a value.
func globMatch(pattern, value string) bool {
	parts := strings.Split(pattern, "*")
	if len(parts) == 1 {
		return pattern == value
	}
	if !strings.HasPrefix(value, parts[0]) {
		return false
	}
	value = value[len(parts[0]):]
	last := parts[len(parts)-1]
	for _, p := range parts[1 : len(parts)-1] {
		i := strings.Index(value, p)
		if i < 0 {
			return false
		}
		value = value[i+len(p):]
	}
	return len(value) >= len(last) && strings.HasSuffix(value, last)
}

// CarveOut returns the pattern of a carve-out, a specifier beginning
// with "!", and whether the rule is one. A carve-out never matches on
// its own; it cancels a match of another rule in the same list, for
// the same tool, from a source it does not rank below, when its
// pattern matches the subject. The pattern is the tool's to
// interpret, as any specifier is.
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
	// The parentheses are checked over the whole string before any
	// token is read, so an unbalanced one is the error even after a
	// token that is bad in another way, as agentskill reports it.
	var tokens []string
	depth, start := 0, -1
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
			if start >= 0 {
				tokens = append(tokens, s[start:i])
				start = -1
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
	if start >= 0 {
		tokens = append(tokens, s[start:])
	}
	var rules []Rule
	for _, tok := range tokens {
		r, err := parseRule(tok)
		if err != nil {
			return nil, err
		}
		rules = append(rules, r)
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
	// The specifier runs to the parenthesis that closes the first one,
	// which must end the token: "Bash(a)(b)" is not the specifier
	// "a)(b". ParseRules has already refused a token whose parentheses
	// do not balance, so that parenthesis exists.
	end, depth := open, 0
	for ; end < len(tok); end++ {
		if tok[end] == '(' {
			depth++
		} else if tok[end] == ')' {
			depth--
			if depth == 0 {
				break
			}
		}
	}
	if end != len(tok)-1 {
		return Rule{}, fmt.Errorf("agentpolicy: rule %q: text after the specifier", tok)
	}
	spec := tok[open+1 : end]
	switch spec {
	case "":
		return Rule{}, fmt.Errorf("agentpolicy: rule %q: empty specifier", tok)
	case "!":
		return Rule{}, fmt.Errorf("agentpolicy: rule %q: empty carve-out", tok)
	}
	return Rule{Tool: tok[:open], Spec: spec}, nil
}
