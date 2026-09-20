package guard

import (
	"context"
	"encoding/json"
	"fmt"
)

// Limit blocks a subject whose wire form is over maxBytes: the input
// before a model call, or the output of a turn. Size is measured as
// the JSON encoding of the items, which is what a server sees.
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
		if len(data) > maxBytes {
			return block(fmt.Sprintf("%s is %d bytes, over the %d byte limit", noun(subject), len(data), maxBytes)), nil
		}
		return allow, nil
	})
}
