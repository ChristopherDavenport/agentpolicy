package guard

import (
	"context"
	"regexp"
)

// Deny blocks a subject whose text matches any of the patterns. Every
// text field is checked: message parts, a function call's arguments,
// a function call output, a reasoning summary. The reason names the
// first pattern that matched.
func Deny(patterns ...*regexp.Regexp) Guard {
	return New("deny", func(_ context.Context, subject any) (Verdict, error) {
		items, ok := items(subject)
		if !ok {
			return allow, nil
		}
		matched := ""
		eachText(items, func(s *string) bool {
			for _, p := range patterns {
				if p.MatchString(*s) {
					matched = p.String()
					return false
				}
			}
			return true
		})
		if matched != "" {
			return block(`matched denied pattern "` + matched + `"`), nil
		}
		return allow, nil
	})
}
