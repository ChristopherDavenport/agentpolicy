package agentpolicy

// Tools is a tool set split the way the presets need it: the tools
// that read, the tools that edit, and the tools that execute. The
// split is the product's; the presets only name the tools.
type Tools struct {
	Read    []string
	Edit    []string
	Execute []string
}

// Suggest is Codex's most conservative mode: reads run, everything
// that changes the world asks, and so does a tool the split does not
// name.
func Suggest(t Tools) Policy {
	return Policy{
		Allow:   bare(t.Read),
		Ask:     bare(t.Edit, t.Execute),
		Default: Ask(),
	}
}

// AutoEdit lets reads and edits run and asks for commands, and for a
// tool the split does not name.
func AutoEdit(t Tools) Policy {
	return Policy{
		Allow:   bare(t.Read, t.Edit),
		Ask:     bare(t.Execute),
		Default: Ask(),
	}
}

// FullAuto runs every tool the split names without asking; the
// confinement is the sandbox's. A tool the split does not name still
// asks, so a tool added later by a plugin does not run unseen.
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
