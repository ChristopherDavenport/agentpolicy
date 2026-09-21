package guard

import (
	"context"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/ChristopherDavenport/openresponses"
)

// Pattern is a named secret shape.
type Pattern struct {
	Name   string
	Regexp *regexp.Regexp
}

// DefaultSecrets are the shapes [Secrets] and [Redact] look for when
// given none: cloud and API keys with a recognisable prefix, tokens of
// the common hosting and chat services, private key blocks, whole when
// the END marker is present and the BEGIN line alone otherwise, and
// JSON web tokens. Patterns given to either guard replace the list; a
// product that adds its own appends to it.
var DefaultSecrets = []Pattern{
	{Name: "aws_access_key", Regexp: regexp.MustCompile(`\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`)},
	{Name: "github_token", Regexp: regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9]{36,}\b`)},
	{Name: "github_pat", Regexp: regexp.MustCompile(`\bgithub_pat_[A-Za-z0-9_]{22,}\b`)},
	{Name: "slack_token", Regexp: regexp.MustCompile(`\bxox[baprs]-[A-Za-z0-9-]{10,}\b`)},
	{Name: "google_api_key", Regexp: regexp.MustCompile(`\bAIza[0-9A-Za-z_-]{35}\b`)},
	{Name: "openai_key", Regexp: regexp.MustCompile(`\bsk-(?:[A-Za-z0-9]+-)?[A-Za-z0-9_-]{20,}\b`)},
	{Name: "private_key", Regexp: regexp.MustCompile(`-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----[\s\S]*?-----END (?:[A-Z]+ )?PRIVATE KEY-----|-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----`)},
	{Name: "jwt", Regexp: regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b`)},
}

// Secrets blocks a subject in which a secret appears, the input before
// a model call or the output of a turn, with the first pattern's name
// as the reason. With no patterns it uses [DefaultSecrets].
func Secrets(patterns ...Pattern) Guard {
	patterns = orDefault(patterns)
	return New("secrets", func(_ context.Context, subject any) (Verdict, error) {
		items, ok := items(subject)
		if !ok {
			return allow, nil
		}
		if name := find(items, patterns); name != "" {
			return block("secret detected: " + name), nil
		}
		return allow, nil
	})
}

// Redact rewrites the input before a model call, and a message before
// the transcript keeps it, replacing every secret with
// "[REDACTED <name>]", so the model never reads one and the session
// records what the model saw and said. The output of a turn cannot be
// rewritten, since it is in the transcript already, so there Redact
// stops the run as [Secrets] does. With no patterns it uses
// [DefaultSecrets].
func Redact(patterns ...Pattern) Guard {
	patterns = orDefault(patterns)
	return New("redact", func(_ context.Context, subject any) (Verdict, error) {
		switch s := subject.(type) {
		case Input, Message:
			items, _ := items(s)
			count := 0
			var names []string
			out, changed := rewrite(items, func(text string) string {
				for _, p := range patterns {
					text = p.Regexp.ReplaceAllStringFunc(text, func(string) string {
						count++
						if !slices.Contains(names, p.Name) {
							names = append(names, p.Name)
						}
						return "[REDACTED " + p.Name + "]"
					})
				}
				return text
			})
			if !changed {
				return allow, nil
			}
			word := "secrets"
			if count == 1 {
				word = "secret"
			}
			return Verdict{Action: allow.Action, Reason: fmt.Sprintf("redacted %d %s: %s", count, word, strings.Join(names, ", ")), Items: out}, nil
		case Output:
			items, _ := items(s)
			if name := find(items, patterns); name != "" {
				return block("secret detected: " + name), nil
			}
		}
		return allow, nil
	})
}

func orDefault(patterns []Pattern) []Pattern {
	if len(patterns) == 0 {
		return DefaultSecrets
	}
	return patterns
}

// find returns the name of the first pattern found in the items, in
// pattern order within each text field.
func find(items openresponses.Items, patterns []Pattern) string {
	name := ""
	eachText(items, func(s *string) bool {
		for _, p := range patterns {
			if p.Regexp.MatchString(*s) {
				name = p.Name
				return false
			}
		}
		return true
	})
	return name
}
