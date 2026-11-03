package agentpolicy

import (
	"encoding/json"
	"fmt"

	"github.com/ChristopherDavenport/agentturn"
	"github.com/ChristopherDavenport/openresponses"
)

// VerdictNS is the namespace a [Verdict] is recorded under, so a reader
// of a session recognises one without knowing the product that wrote
// it. See [Verdict.Record].
const VerdictNS = "agentpolicy:verdict"

// verdictRecord is a verdict as a session holds it: the action as a
// word, the rule as its token with its source's name and hash and its
// note, and every member that is empty left out.
type verdictRecord struct {
	RunID      string `json:"run_id,omitempty"`
	Turn       int    `json:"turn,omitempty"`
	CallID     string `json:"call_id,omitempty"`
	Tool       string `json:"tool,omitempty"`
	Guard      string `json:"guard,omitempty"`
	Action     string `json:"action"`
	Rule       string `json:"rule,omitempty"`
	Source     string `json:"source,omitempty"`
	SourceHash string `json:"source_hash,omitempty"`
	Note       string `json:"note,omitempty"`
	Reason     string `json:"reason,omitempty"`
	By         string `json:"by,omitempty"`
	Held       bool   `json:"held,omitempty"`
	Subject    string `json:"subject,omitempty"`
	Confined   string `json:"confined,omitempty"`
	// Grant and Scope say what a grant or a revocation did and the
	// grant scope it was made under; Source names its source.
	Grant string `json:"grant,omitempty"`
	Scope string `json:"scope,omitempty"`
	// Quarantined names the items an input guard quarantined, each by
	// reference: its type, id and call ID, never its content.
	Quarantined []itemRef `json:"quarantined,omitempty"`
}

// Record returns the namespace and the bytes of the custom entry a
// product writes for the verdict, beside the decision the loop's
// recorder writes for the call, so every product on this stack records
// a verdict under one name in one shape:
//
//	ns, data := v.Record()
//	_, err := recorder.Annotate(ctx, ns, json.RawMessage(data))
//
// The bytes are JSON already, which is why they are handed over as a
// json.RawMessage: a recorder that encodes what it is given would
// write a []byte as a base64 string.
//
// The entry is a JSON object: run_id, turn, call_id, tool and guard as
// the verdict names them; action as "allow", "block" or "defer"; rule
// as its token, "bash(git push:*)", with source naming the file it
// came from, source_hash the Source.Hash of that file or frontmatter,
// so a review of the session can say which version of a skill or a
// settings file a grant or a decision was built from, and note saying
// why it exists; then reason, by, held, subject and confined; and
// quarantined, a reference to each item an input guard quarantined,
// {type, id, call_id}, with no content, so the item's text is redacted
// with the entry that holds it and not copied here. A grant or a
// revocation adds grant, its [GrantKind], and scope, the grant scope
// it was made under, and names its source in source even when it has
// no rule, so a reader rebuilds the grants in force from these members
// and never parses reason for them. A member the verdict leaves empty
// is left out, except action, so a record written before these
// members existed reads the same. A record is strings,
// numbers and flags, so encoding it cannot fail; a caller that wants
// an error of its own marshals the value itself.
func (v Verdict) Record() (ns string, data []byte) {
	rec := verdictRecord{
		RunID:    v.RunID,
		Turn:     v.Turn,
		CallID:   v.CallID,
		Tool:     v.Tool,
		Guard:    v.Guard,
		Action:   actionWord(v.Action),
		Reason:   v.Reason,
		By:       v.By,
		Held:     v.Held,
		Subject:  v.Subject,
		Confined: v.Confined,
		Grant:    string(v.Grant),
		Source:   v.Source,
		Scope:    v.Scope,
	}
	for _, item := range v.Quarantined {
		rec.Quarantined = append(rec.Quarantined, refOf(item))
	}
	if v.Rule != nil {
		rec.Rule, rec.SourceHash, rec.Note = v.Rule.String(), v.Rule.Source.Hash, v.Rule.Note
		if v.Rule.Source.Name != "" {
			rec.Source = v.Rule.Source.Name
		}
	}
	data, err := json.Marshal(rec)
	if err != nil {
		// Unreachable: every member is a string, an int or a bool.
		// Recording something a reader can see went wrong beats
		// recording nothing.
		data = fmt.Appendf(nil, "{%q:%q}", "error", err.Error())
	}
	return VerdictNS, data
}

// itemRef names an item without its content, so a quarantined item's
// text, an injected instruction or a secret, is not copied out of the
// entry that holds it, past the redaction a record applies to that
// entry: the type, and the id and call ID when the item has them.
type itemRef struct {
	Type   string `json:"type"`
	ID     string `json:"id,omitempty"`
	CallID string `json:"call_id,omitempty"`
}

// refOf is the reference to item, read from its wire form.
func refOf(item openresponses.Item) itemRef {
	ref := itemRef{}
	if item == nil {
		return ref
	}
	ref.Type = item.ItemType()
	if data, err := json.Marshal(item); err == nil {
		_ = json.Unmarshal(data, &ref)
	}
	return ref
}

// actionWord names an action as a session holds it.
func actionWord(a agentturn.ToolAction) string {
	switch a {
	case agentturn.Allow:
		return "allow"
	case agentturn.Block:
		return "block"
	case agentturn.Defer:
		return "defer"
	}
	return fmt.Sprintf("action(%d)", int(a))
}
