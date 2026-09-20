package guard

import "github.com/ChristopherDavenport/openresponses"

// eachText visits every text field of the items, in order, and stops
// when visit returns false: the parts of a message, a function call's
// arguments, a function call output's text or parts, and a reasoning
// item's summary and content. A compaction, an item reference and an
// unknown item carry no text a guard reads.
func eachText(items openresponses.Items, visit func(*string) bool) {
	for _, item := range items {
		if !eachItemText(item, visit) {
			return
		}
	}
}

func eachItemText(item openresponses.Item, visit func(*string) bool) bool {
	switch v := item.(type) {
	case *openresponses.Message:
		return eachContentText(v.Content, visit)
	case *openresponses.FunctionCall:
		return visit(&v.Arguments)
	case *openresponses.FunctionCallOutput:
		if v.Output.Parts != nil {
			return eachContentText(v.Output.Parts, visit)
		}
		return visit(&v.Output.Text)
	case *openresponses.ReasoningItem:
		return eachContentText(v.Summary, visit) && eachContentText(v.Content, visit)
	}
	return true
}

func eachContentText(parts openresponses.Contents, visit func(*string) bool) bool {
	for _, part := range parts {
		var s *string
		switch p := part.(type) {
		case *openresponses.InputText:
			s = &p.Text
		case *openresponses.OutputText:
			s = &p.Text
		case *openresponses.Refusal:
			s = &p.Refusal
		case *openresponses.Text:
			s = &p.Text
		case *openresponses.SummaryText:
			s = &p.Text
		case *openresponses.ReasoningText:
			s = &p.Text
		default:
			continue
		}
		if !visit(s) {
			return false
		}
	}
	return true
}

// rewrite applies fn to every text field of a deep copy of the items
// and returns the copy and whether any field changed. The items given
// are not modified.
func rewrite(items openresponses.Items, fn func(string) string) (openresponses.Items, bool) {
	out := items.Clone()
	changed := false
	eachText(out, func(s *string) bool {
		if r := fn(*s); r != *s {
			*s = r
			changed = true
		}
		return true
	})
	return out, changed
}
