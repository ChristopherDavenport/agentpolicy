package agentpolicy

// The presets are approximations of Codex's three approval modes, not
// the modes themselves. The reference pairs each mode with a sandbox
// policy and a network policy, and this module decides without
// confining: it has no sandbox, no filesystem scope and no network
// rule, so a preset carries the approval half and the product carries
// the rest. They are kept here as worked examples of the grammar, so
// two products do not write three slightly different versions of the
// same three policies, and a product that needs the reference's
// behaviour exactly writes its own rules.

// Tools is a tool set split the way the presets need it: the tools
// that read, the tools that edit, and the tools that execute. The
// split is the product's; the presets only name the tools.
type Tools struct {
	Read    []string
	Edit    []string
	Execute []string
}

// Suggest approximates Codex's most conservative mode: reads run,
// everything that changes the world asks, and so does a tool the split
// does not name. The reference also confines the run to a read-only
// sandbox, which is the product's to arrange.
func Suggest(t Tools) Policy {
	return Policy{
		Allow:   bare(t.Read),
		Ask:     bare(t.Edit, t.Execute),
		Default: Ask(),
	}
}

// AutoEdit approximates Codex's middle mode: reads and edits run,
// commands ask, and so does a tool the split does not name. The
// reference confines the edits to the workspace, which is the
// product's to arrange.
func AutoEdit(t Tools) Policy {
	return Policy{
		Allow:   bare(t.Read, t.Edit),
		Ask:     bare(t.Execute),
		Default: Ask(),
	}
}

// FullAuto approximates Codex's unattended mode: every tool the split
// names runs without asking, and the confinement is the sandbox's,
// which is the product's to arrange. A tool the split does not name
// still asks, so a tool added later by a plugin does not run unseen.
func FullAuto(t Tools) Policy {
	return Policy{
		Allow:   bare(t.Read, t.Edit, t.Execute),
		Default: Ask(),
	}
}

// bare builds bare rules for the names, in order.
func bare(lists ...[]string) []Rule {
	var out []Rule
	for _, names := range lists {
		for _, n := range names {
			out = append(out, Rule{Tool: n})
		}
	}
	return out
}
