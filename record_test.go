package agentpolicy

import (
	"testing"

	"github.com/ChristopherDavenport/agentturn"
)

func TestVerdictRecord(t *testing.T) {
	project := Source{Name: "project", Path: ".agent/settings.json", Rank: 1}
	tests := []struct {
		name string
		v    Verdict
		want string
	}{
		{name: "a decision", v: Verdict{RunID: "run_1", Turn: 2, CallID: "call_1", Tool: "bash", Action: agentturn.Block, Rule: &Rule{Tool: "bash", Spec: "curl:*", Source: project, Note: "use fetch"}, Reason: "denied by bash(curl:*): use fetch", By: ByPolicy, Subject: "curl x", Confined: "landlock+seccomp"},
			want: `{"run_id":"run_1","turn":2,"call_id":"call_1","tool":"bash","action":"block","rule":"bash(curl:*)","source":"project","note":"use fetch","reason":"denied by bash(curl:*): use fetch","by":"policy","subject":"curl x","confined":"landlock+seccomp"}`},
		// A skill grant's source carries the frontmatter's digest, so the
		// session says which version of the skill the grant was built
		// from, not only its name (#64).
		{name: "a grant from a hashed source", v: Verdict{Tool: "bash", Action: agentturn.Allow, Rule: &Rule{Tool: "bash", Spec: "git:*", Source: Source{Name: "skill:deploy", Hash: "sha256:9f2c", Trusted: true, Rank: 2}}, Reason: "granted bash(git:*) by skill:deploy", By: ByPolicy},
			want: `{"tool":"bash","action":"allow","rule":"bash(git:*)","source":"skill:deploy","source_hash":"sha256:9f2c","reason":"granted bash(git:*) by skill:deploy","by":"policy"}`},
		// A grant's and a revocation's record names its kind, source and
		// scope as members, so a reader rebuilds the grants in force
		// without parsing the reason (agentkit#80).
		{name: "a grant set's grant under a scope", v: Verdict{Tool: "bash", Action: agentturn.Allow, Rule: &Rule{Tool: "bash", Spec: "git:*", Source: Source{Name: "skill:deploy", Trusted: true, Rank: 1}}, Reason: "granted bash(git:*) by skill:deploy", By: ByPolicy, Grant: KindGrantSet, Source: "skill:deploy", Scope: "conv-1"},
			want: `{"tool":"bash","action":"allow","rule":"bash(git:*)","source":"skill:deploy","reason":"granted bash(git:*) by skill:deploy","by":"policy","grant":"grant_set","scope":"conv-1"}`},
		{name: "a revocation", v: Verdict{Action: agentturn.Block, Reason: "revoked the rules granted by skill:deploy", By: ByPolicy, Grant: KindRevoke, Source: "skill:deploy", Scope: "conv-1"},
			want: `{"action":"block","source":"skill:deploy","reason":"revoked the rules granted by skill:deploy","by":"policy","grant":"revoke","scope":"conv-1"}`},
		{name: "a scope's revocation", v: Verdict{Action: agentturn.Block, Reason: "revoked the rules granted without a scope", By: ByPolicy, Grant: KindRevokeScope},
			want: `{"action":"block","reason":"revoked the rules granted without a scope","by":"policy","grant":"revoke_scope"}`},
		// An activation carries the set as kept, so a reader rebuilds it
		// from the record alone, the rules a set only restricts with and
		// a note included.
		{name: "an activation", v: Verdict{Action: agentturn.Allow, Reason: "activated the rules granted by skill:deploy", By: ByPolicy, Grant: KindActivate, Source: "skill:deploy", Scope: "conv-1",
			Set: &RuleSet{Source: Source{Name: "skill:deploy", Hash: "sha256:9f2c", Trusted: true, Rank: 1},
				Allow: []Rule{{Tool: "bash", Spec: "git:*"}}, Deny: []Rule{{Tool: "web_fetch", Note: "no network"}}},
			Refused: []Refusal{{Rule: Rule{Tool: "edit"}, Reason: "edit from managed outranks the grant"}}},
			want: `{"action":"allow","source":"skill:deploy","source_hash":"sha256:9f2c","reason":"activated the rules granted by skill:deploy","by":"policy","grant":"activate","scope":"conv-1","set":{"rank":1,"trusted":true,"allow":["bash(git:*)"],"deny":["web_fetch"],"notes":{"deny":{"web_fetch":"no network"}}},"refused":[{"rule":"edit","reason":"edit from managed outranks the grant"}]}`},
		// A rule in two lists keeps the note of each.
		{name: "an activation with one rule in two lists", v: Verdict{Action: agentturn.Allow, Reason: "activated the rules granted by skill:web", By: ByPolicy, Grant: KindActivate, Source: "skill:web",
			Set: &RuleSet{Deny: []Rule{{Tool: "web_fetch", Spec: "evil.com:*", Note: "blocked host"}}, Ask: []Rule{{Tool: "web_fetch", Spec: "evil.com:*", Note: "asked host"}}}},
			want: `{"action":"allow","source":"skill:web","reason":"activated the rules granted by skill:web","by":"policy","grant":"activate","set":{"deny":["web_fetch(evil.com:*)"],"ask":["web_fetch(evil.com:*)"],"notes":{"ask":{"web_fetch(evil.com:*)":"asked host"},"deny":{"web_fetch(evil.com:*)":"blocked host"}}}}`},
		{name: "an activation that keeps nothing", v: Verdict{Action: agentturn.Allow, Reason: "activated the rules granted by the product", By: ByPolicy, Grant: KindActivate, Set: &RuleSet{}},
			want: `{"action":"allow","reason":"activated the rules granted by the product","by":"policy","grant":"activate","set":{}}`},
		{name: "a grant over an ask rule", v: Verdict{Tool: "bash", Action: agentturn.Allow, Rule: &Rule{Tool: "bash", Spec: "git push origin:*", Source: Source{Name: "user", Rank: 1}}, Reason: "granted bash(git push origin:*) over bash(git push:*)", By: ByPolicy, Grant: KindGrantOver, Source: "user",
			Over: &Rule{Tool: "bash", Spec: "git push:*", Source: Source{Name: "project", Rank: 1}}},
			want: `{"tool":"bash","action":"allow","rule":"bash(git push origin:*)","source":"user","reason":"granted bash(git push origin:*) over bash(git push:*)","by":"policy","grant":"grant_over","over":{"rule":"bash(git push:*)","source":"project"}}`},
		{name: "a held call", v: Verdict{RunID: "run_1", CallID: "call_2", Tool: "read", Action: agentturn.Defer, Held: true, Reason: "held for approval: allowed by default", By: ByPolicy},
			want: `{"run_id":"run_1","call_id":"call_2","tool":"read","action":"defer","reason":"held for approval: allowed by default","by":"policy","held":true}`},
		{name: "a guard's verdict", v: Verdict{RunID: "run_1", Guard: "secrets", Action: agentturn.Allow},
			want: `{"run_id":"run_1","guard":"secrets","action":"allow"}`},
		{name: "the zero verdict", want: `{"action":"allow"}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ns, data := tt.v.Record()
			if ns != "agentpolicy:verdict" || string(data) != tt.want {
				t.Errorf("Record = %s %s\nwant %s", ns, data, tt.want)
			}
		})
	}
}
