package guard

import (
	"context"
	"encoding/json"
	"fmt"
)

// Limit blocks a subject whose wire form is over maxBytes: the input
// before a model call, or the output of a turn. Size is measured as
// the JSON encoding of the items plus, for an input, the instructions,
// which is what a server sees: a request carrying a hundred kilobytes
// of AGENTS.md and one short message is a hundred kilobytes.
func Limit(maxBytes int) Guard {
	return New("limit", func(_ context.Context, subject any) (Verdict, error) {
		items, ok := items(subject)
		if !ok {
			return allow, nil
		}
		data, err := json.Marshal(items)
		if err != nil {
			return Verdict{}, fmt.Errorf("encode %s: %w", noun(subject), err)
		}
		size := len(data) + len(instructions(subject))
		if size > maxBytes {
			return block(fmt.Sprintf("%s is %d bytes, over the %d byte limit", noun(subject), size, maxBytes)), nil
		}
		return allow, nil
	})
}
