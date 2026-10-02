package agentpolicy

import (
	"encoding/json"
	"fmt"

	"github.com/ChristopherDavenport/agentturn"
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
// why it exists; then reason, by, held, subject and confined. A member
// the verdict leaves empty is left out, except action. A verdict is
// strings, numbers and a flag, so encoding it cannot fail; a caller
// that wants an error of its own marshals the value itself.
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
	}
	if v.Rule != nil {
		rec.Rule, rec.Source, rec.SourceHash, rec.Note = v.Rule.String(), v.Rule.Source.Name, v.Rule.Source.Hash, v.Rule.Note
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
