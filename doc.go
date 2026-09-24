// Package agentpolicy decides what an agent may do: a rule grammar over
// tool calls, an engine that becomes the loop's BeforeToolCall hook, a
// journal of every verdict, and an answer source for the calls the
// engine defers. Guards over content live in the guard package and
// become the loop's BeforeModelCall, OutputGuard and
// ShouldStopAfterTurn hooks; a guard and a reviewer backed by a model
// live in classify.
//
// A policy is three lists of rules and a default:
//
//	rules, _ := agentpolicy.ParseRules("bash(git status:*) bash(npm test:*)")
//	eng, err := agentpolicy.Build(agentpolicy.Policy{
//		Allow:   rules,
//		Deny:    must(agentpolicy.ParseRules("bash(rm:*)")),
//		Default: agentpolicy.Ask(),
//	}, map[string]agentpolicy.ToolMatcher{
//		"bash": {Match: agentpolicy.PrefixMatcher("command")},
//	})
//	cfg.BeforeToolCall = eng.BeforeToolCall()
//
// Precedence is deny, then ask, then allow, then the default, always. A
// deny blocks the call with a reason that names the rule; an ask defers
// it to the caller, who answers through the loop's Resume, and holds
// the calls of the same batch the policy allows, which Engine.Release
// answers from the caller's answer. When a tool's matcher splits a
// call into several subjects, a shell command into its subcommands
// say, the call is denied if any subject is, asked about if any
// subject is, and allowed only when every subject is.
//
// A deny rule with no specifier, or one whose tool name is a glob,
// takes the tool out of the request rather than refusing its calls:
// Engine.ToolProvider is the hook value that does it. One engine
// serves every agent of a product, since the policy is the product's
// and not a loop's, and it remembers what it defers under the call's
// own run. The rules change under it: Engine.SetPolicy for a tool list
// that changed, Engine.Grant and Engine.GrantOver for an "always
// allow", and Engine.GrantSet for a rule set that lasts as long as its
// source, a skill's allowed-tools, which Engine.Revoke takes back.
//
// The engine never calls a model or opens a socket: the same policy and
// the same call always give the same verdict. Every verdict, every
// grant and every reviewer's answer reaches the observer exactly once,
// so a product can record it beside the session.
package agentpolicy
