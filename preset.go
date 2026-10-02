package agentpolicy

// The presets are approximations of Codex's three approval modes, not
// the modes themselves. The reference pairs each mode with a sandbox
// policy and a network policy, and this module decides without
// confining: it has no sandbox, no filesystem scope and no network
// rule, so a preset carries the approval half and the product carries
// the rest. The halves meet where a tool says so: a call whose tool
// reports it runs confined, through agenttool.Confined, is not asked
// about by a preset's bare ask rule, as the reference does not ask
// about a sandboxed command, and a call that leaves the sandbox still
// asks. See [WithConfinement]. They are kept here as worked examples of the grammar, so
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
// everything that changes the world asks unless its tool says the call
// runs confined, and a tool the split does not name asks. The
// reference also confines the run to a read-only sandbox, which is the
// product's to arrange.
//
// Confinement is one bit: a tool says a call is confined and what
// confines it, not what that sandbox permits. Under a sandbox that
// permits writes, workspace-write, Suggest therefore allows every
// confined command AutoEdit allows, "rm -rf src" included. A product
// whose sandbox permits writes passes WithConfinement(nil) with
// Suggest, or a reading that answers confined only for a read-only
// sandbox, so its commands ask.
//
// A host whose tools are discovered at run time replaces the default
// with [Policy.WithDefault], or names the discovered tools in the
// split and follows its tool list with [Engine.SetPolicy].
func Suggest(t Tools) Policy {
	return Policy{
		Allow:   bare(t.Read),
		Ask:     bare(t.Edit, t.Execute),
		Default: Ask(),
	}
}

// AutoEdit approximates Codex's middle mode: reads and edits run,
// commands ask unless their tool says they run confined, and a tool
// the split does not name asks. The reference confines the edits to
// the workspace, which is the product's to arrange. A confined command
// is allowed whatever its sandbox permits; see [Suggest]. A host whose
// tools are discovered at run time replaces the default with
// [Policy.WithDefault], or names the discovered tools in the split and
// follows its tool list with [Engine.SetPolicy].
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
// still asks, so a tool added later by a plugin does not run unseen; a
// host that wants such a tool to run replaces the default with
// [Policy.WithDefault], knowing what it gives up, or names the
// discovered tools in the split and follows its tool list with
// [Engine.SetPolicy].
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
