# RFC 0001: Agent Policy

Status: draft 0.1
Author: Christopher Davenport
Discussion: to be opened against this repository. The Go module at its
root is the reference binding. agentturn RFC 0001 is the loop whose
hooks it fills, agenttool RFC 0001 the tool contract whose properties
it reads, and agentsession RFC 0001 the record its verdicts land in.

## Summary

A policy decides what an agent may do, and a guard decides what may
enter or leave its window. Both answer with the loop's own vocabulary,
allow, block or defer, give a reason in stable text, and report a
**verdict** that a recorder writes beside the call or the content it
was about.

A policy is three lists of **rules**, deny, ask and allow, and a
default. A rule is a tool name, or a tool name with a **specifier** in
parentheses: `Bash`, `Bash(git status:*)`. That is also the grammar of
a skill's `allowed-tools`, so a skill and a policy read one string one
way. What a specifier means belongs to the tool, through a **matcher**
the host registers for it. Precedence is deny, then ask, then allow,
then the default, whatever the order of the lists and whatever the
sources the rules came from.

This document states what the Go module carries in doc comments: the
grammar and its errors; the matcher contract and the two reference
matchers; how a call is split into subjects and how their verdicts
fold; how sources merge, rank and scope a carve-out; the precedence as
an algorithm; confinement; the batch hold; grants; the answers to a
deferred call; the guard contract over content; and the verdict and its
record. The Go binding is a table against it, and a corpus of JSON
fixtures in `testdata/policy/` is what a second implementation runs.

## Motivation

The precedence was stated in prose in three places, the package doc,
the `Policy` type and the README, and held only by Go tests (#12). The
grammar was shared with agentskill, which parses `allowed-tools` with
it, by authorship: one person wrote both parsers, and they agreed
because that person remembered to make them agree. agentskill #3 was
the first place they did not: `Bash()` parsed as a bare rule there and
so granted every Bash call a skill's author meant to narrow. A corpus
both sides ran would have caught it on both at once.

The rest of the stack is written down. agentturn RFC 0001 says the
loop has a decision seam before each call and that "permissions are a
non-goal"; agenttool RFC 0001 says a tool reports whether a call runs
confined and "nothing here decides whether a call may run";
agentsession RFC 0001 records a decision with a decider and a reason.
This module is the thing all three defer to, and it was the one piece
with no specification. A front that wants to show which of a user's
rules will match a call before the call is made had two options:
reimplement the precedence and drift, or round-trip to Go to answer a
question with no I/O in it.

Writing the corpus found the two parsers still disagreed. Given
`Bash(a)(b)`, agentpolicy read the specifier `a)(b` and agentskill
refused the token; given a no-break space between two names,
agentskill split them and agentpolicy read one tool name. This draft
takes agentskill's reading of parentheses and agentpolicy's of
whitespace, and the Go module's parser changes to match; agentskill's
whitespace is the other half.

This RFC is the specification #12 asked for. Apart from that parser
fix it changes no behaviour of the Go module at draft 0.1. Where the
module falls short of what is written, or where what is written is
itself in question, the gap is listed under open questions with the
issue that tracks it.

## Goals

- **One grammar.** A rule list is one string with one parse, the same
  for a settings file, a skill and a grant, with errors named so two
  parsers agree on what they refuse.
- **One precedence.** A pure function from rules, matchers, a call and
  what the call's tool says of its sandbox to a verdict, with no I/O
  and no model, stated as an algorithm.
- **Fail closed.** A default must be chosen; a rule that could never
  fire does not build; a splitter or a hook that fails blocks or asks.
- **Reasons as contract.** The text the model reads for a refused call
  and the text a prompt shows for an asked one are fixed, so a model
  sees the same refusal under every implementation.
- **Every verdict recorded.** Each decision, hold, release, grant,
  guard verdict and reviewer's answer is a verdict with one record
  shape under one namespace.
- **Bindable and testable.** The contract is language-neutral; the Go
  module is a binding of it, and the corpus is the test.

## Non-goals

- Knowing what a tool does. What `git:*` means is the tool's; the host
  registers a matcher, and a splitter when one call is several
  subjects. There is no shell parser here.
- Sandboxing. This document decides; it does not confine. A tool says
  whether a call runs confined, under agenttool RFC 0001, and a policy
  reads that.
- The approval interface. A deferred call ends the run with the call
  pending, under agentturn RFC 0001; a front asks and resumes.
- Content classification models. A guard or a reviewer backed by a
  model is a binding's package; which model and which rubric is the
  host's.
- A settings file format. Where rules are stored, how a note is
  written beside a rule, and how a source is named on disk are the
  host's. This document starts at a parsed rule list with a source.

## Terminology

The key words MUST, MUST NOT, SHOULD and MAY are to be interpreted as in
RFC 2119.

- **Rule**: a tool name, a specifier or none, a source and a note.
- **Specifier**: the text inside a rule's parentheses. Its meaning is
  its tool's matcher's.
- **Carve-out**: a rule whose specifier begins with `!`. It never
  matches on its own; it cancels a match of another rule.
- **Tool-name glob**: a rule whose tool name contains `*`, naming every
  tool whose name it matches.
- **List**: the deny, ask or allow rules of a policy.
- **Policy**: three lists, a default, the sources the rules came from,
  and the allow rules withheld from untrusted sources.
- **Source**: where a set of rules came from: a name, a path and a hash
  that identify it, whether the user trusts it, and a rank.
- **Matcher**: a function from a specifier and one subject's arguments
  to whether the specifier matches.
- **Subject**: one thing a policy is evaluated against: arguments, a
  tool whose rules apply to them, and text a prompt shows.
- **Splitter**: a function from a call's arguments to its subjects.
- **Confinement**: what a call's tool says of where the call runs:
  confined or not, and what confines it.
- **Engine**: the runtime form of a policy: the policy in force, the
  matchers, the active grants and the deferred calls.
- **Batch**: the calls of one model response, in the model's order, as
  agentturn RFC 0001 defines it.
- **Hold**: a call the policy allows that is deferred because another
  call of its batch asks.
- **Grant**: rules added to an engine after it was built: an "always
  allow" answer to a prompt, or a rule set active for as long as its
  source is.
- **Verdict**: what was decided and why, for the record.
- **Decider**: who decided, in agentsession RFC 0001's words: `policy`,
  `agent` or `human`.
- **Guard**: a check over content: a request's input, one assistant
  message, or a finished turn.

## The grammar

A rule list is a string of **tokens** separated by whitespace outside
parentheses. Whitespace is the six ASCII characters space, horizontal
tab, line feed, vertical tab, form feed and carriage return, and no
other: a no-break space, or any other Unicode space, is an ordinary
character, since languages disagree on which of those are whitespace.

1. Scan the string, counting parenthesis depth: `(` adds one and `)`
   takes one away. A `)` at depth zero is an error. Whitespace at
   depth zero ends a token; every other character belongs to one. The
   string ending at a depth above zero is an error.
2. A token with no `(` is a bare rule: its tool name is the token.
3. Otherwise the tool name is everything before the token's first `(`,
   and MUST NOT be empty. The specifier is everything between that `(`
   and the `)` that returns the depth to zero, which MUST be the
   token's last character.

So a specifier MAY contain whitespace, and parentheses as long as they
balance: `Bash(git status:*)`, `Edit(./Finance (2024)/**)`,
`Bash(a(b)c)`. `Bash(a)(b)` is not the specifier `a)(b`, and is an
error. The empty string, and a string of whitespace, is a list of no
rules and no error.

A rule's string form is its tool name, or its tool name with its
specifier in parentheses, which is the token it was parsed from.
Nothing folds case: `Bash` and `bash` are different tool names.

A parser MUST refuse the whole list with one of these errors, naming
the token. Parentheses are checked over the whole string first, before
any token is read, so an unbalanced parenthesis is the error even
when a token before it is bad in another way: `Read Bash() git)` is
`unbalanced_parentheses` naming `git)`. Otherwise the list is refused
at the first bad token, and a token that fails more than one of the
other checks fails the first in the table's order, so `Bash()x` is
`text_after_specifier`:

| kind | when | token named |
| --- | --- | --- |
| `unbalanced_parentheses` | a `)` at depth zero, or the string ends above depth zero | from the token's first character to the stray `)`, or to the end of the string |
| `missing_tool_name` | a token begins with `(` | the token |
| `text_after_specifier` | the `)` closing the specifier is not the token's last character | the token |
| `empty_specifier` | `()` | the token |
| `empty_carve_out` | `(!)` | the token |

`Bash()` is an error and never a bare rule: a bare rule matches every
call of its tool, and an empty specifier written to narrow a grant
MUST NOT widen it.

A **carve-out** is a rule whose specifier begins with `!`; its pattern
is the rest of the specifier. The grammar knows that about a specifier
and nothing else.

A **tool-name glob** is a rule whose tool name contains `*`. `*`
stands for any run of characters, the empty run included, at any
position; every other character stands for itself. `mcp__*` names
every tool of every MCP server.

A rule MAY carry a **note**, a sentence saying why it exists. The note
is not part of the grammar: a parser leaves it empty, and a host's
settings reader fills it from a comment or a field beside the rule.
Two rules that differ only in their notes are the same rule.

## Matchers

A matcher answers whether a specifier matches one subject's arguments.
The host registers at most one per tool name, and a rule with a
specifier for a tool with no matcher does not build. A matcher MUST be
deterministic: the same specifier and the same arguments give the same
answer.

A matcher reads its specifier as it likes. Two reference matchers are
defined here, each over one string member of an arguments object. For
both, arguments that are not a JSON object, a missing member and a
member that is not a string match nothing.

**Prefix** is the simplest case. A specifier ending in `:*` matches a
value that begins with the rest of the specifier; any other specifier
matches the value exactly. `git:*` matches `git status` and `gitk`.

**Glob** is the pattern a settings file copied from the reference
agent's documentation is written in.

- `*` stands for any run of characters, spaces included, at any
  position: `git log * main` matches `git log --oneline main`, and
  `* --version` matches `node --version`. The space is part of the
  pattern, so `ls *` matches `ls -la` and not `ls` or `lsof`.
- A trailing `:*` is a wildcard at a word boundary, which is a space:
  `P:*` matches a value that `P` matches, or that `P *` matches. `ls:*`
  matches `ls` and `ls -la`, and not `lsof`, and not `ls` followed by a
  tab. `:*` alone matches everything.
- A pattern with no wildcard matches the whole value exactly.

The two differ on purpose. Under prefix, `ls:*` matches `lsof` and `*`
anywhere but a trailing `:*` is literal. A host that reads settings
written for the reference agent registers glob.

## Subjects

A call is one subject, its own arguments, unless its tool's matcher
comes with a **splitter**. A splitter turns a call's arguments into
its subjects, after whatever normalisation the tool needs: a shell tool
splits a command on its operators and strips wrappers, a file tool
resolves a path. Each subject has:

- **args**, the subject as the matchers see it;
- **tool**, when set, the tool whose rules apply to it, as a shell
  redirect target is checked against the file tool's rules; unset is
  the called tool;
- **text**, what a prompt shows for the subject, and what a reason
  cites.

A splitter that fails blocks the call, with its error in the reason. A
splitter that returns no subjects is a failure too, since a call with
no subjects would be allowed by every rule.

## Sources

Every rule carries its **source**:

- **name** identifies the source, keys a grant, and names the file a
  host persists its own rules into. The zero source, with no name, is
  a rule the host built itself.
- **path** and **hash** let a session name the policy in force. Nothing
  in a decision reads them.
- **trusted** says the user trusts the source. An untrusted source's
  allow rules are withheld, since they grant capability, and its deny
  and ask rules apply at once, since they only restrict. A source
  built by hand is untrusted until it says otherwise.
- **rank** orders sources by authority, higher first. Rank decides
  which grant may answer which ask rule and which carve-out reaches
  which rule. Rank never affects precedence between lists: deny before
  ask before allow holds whatever the sources.

### Merge

Merging several sources' rule sets into one policy:

1. Order the sets by rank, highest first, keeping the given order
   between sets of equal rank.
2. Refuse a set whose source has no name, and two sets whose sources
   share a name.
3. For each set in that order, list its source on the policy, stamp
   each of its rules with the source, and append its deny and ask
   rules to the policy's deny and ask lists. Append its allow rules to
   the allow list when the source is trusted, and to the policy's
   withheld list otherwise.
4. Leave the default unset for the host to choose.

The withheld list is not evaluated. It is what a front shows when it
asks whether to trust a source, so the user reads what trusting it
would allow. Trusting a source is merging again with trusted set.

### Aliases

Rules a host did not write are spelled with the reference agent's tool
names, `Bash`, `Read`, `Edit`, and one of those names may govern
several of a host's tools. An **alias table** maps a rule name to the
tool names it governs. Building a policy expands every rule whose tool
name has an entry into one rule per tool, in the entry's order, keeping
the specifier, the source and the note. Expansion is one level: a tool
an entry names is not expanded again. A name with no entry is a tool's
own name.

An alias table MUST NOT have an entry with an empty name, a name
containing `*`, an entry naming no tool, or an entry naming an empty
tool name or one containing `*`.

## Building a policy

Building validates a policy against the matchers and returns an
engine. It MUST refuse, with these error kinds:

| kind | when | text |
| --- | --- | --- |
| `no_default` | the default is unset | `agentpolicy: policy default is not set; use Allow(), Deny() or Ask()` |
| `no_matcher` | a rule has a specifier, a carve-out's included, and its tool has no matcher | `agentpolicy: no matcher for the rule's tool: R` |
| `tool_glob` | a tool-name glob is in the allow list | `agentpolicy: tool-name glob: R is not honoured in the allow list` |
| `tool_glob` | a tool-name glob has a specifier | `agentpolicy: tool-name glob: R takes no specifier` |
| `invalid_rule` | a rule has no tool name, or the alias table is refused | `agentpolicy: rule "R": missing tool name` for the first |

`R` is the rule's string form. The texts matter because a grant's
refusal reports them, and a front shows them. A binding MAY append a
hint to the `no_matcher` text, as the reference appends `; did you mean
T?` when a matcher's tool differs from the rule's only in case; the
corpus uses no rule that draws one. Granting a carve-out is refused
with `agentpolicy: cannot grant a carve-out: R`.

The rules are expanded through the alias table before they are
checked. The default MUST be set explicitly: a deny list written on its
own never allows everything else by accident.

A tool-name glob is honoured in the deny and ask lists, where the
reference agents honour one. It is refused in the allow list, where the
reference refuses it too, and with a specifier, since a glob names no
matcher to read the specifier with.

## Deciding a subject

A subject is decided against the **active lists**: the policy's lists,
followed by the kept lists of every active grant set in activation
order (see [Grant sets](#grant-sets)). The inputs are the tool whose
rules apply, the subject's arguments, and the call's confinement.

A rule **fires** for a tool `T` and arguments `A`, within the list `L`
it belongs to, when all of these hold:

1. its tool name is `T`, or is a tool-name glob that matches `T`;
2. it is not a carve-out;
3. it is bare, or its tool's matcher matches its specifier against `A`;
4. no carve-out in `L` whose tool name is the rule's tool name, and
   whose source's rank is at or above the rule's source's rank, has a
   pattern its tool's matcher matches against `A`.

A carve-out therefore reaches a rule of any source it does not rank
below, and never one of a source that outranks it: a repository's
`read(!.env.example)` cannot open a `read(.env:*)` an administrator
denied.

The precedence, in order:

1. **Deny.** The first deny rule that fires blocks the subject.
2. **Ask.** Take the ask rules that fire, in order. Pass over one that
   an active grant set shadows. When the call runs confined, pass over
   a bare one, remembering the first passed over for confinement. The
   first ask rule not passed over defers the subject.
3. **Confined.** When a bare ask rule was passed over for confinement
   and none deferred, the subject is allowed, and that rule is the
   verdict's.
4. **Allow.** The first allow rule that fires allows the subject.
5. **Default.** The default applies, with no rule.

The first rule that fires within a list is the one a verdict names, so
a merge that puts the most authoritative source first makes it the one
cited.

The reason is stable text. `R` is the rule's string form, and `C`, the
rule as a reason cites it, is `R`, or `R: note` when the rule has a
note and its source is the host's own or trusted. A note from an
untrusted source is left out, since the model would read a
repository's text in the harness's voice; it stays on the verdict's
rule for the record and the front.

| outcome | action | rule | reason |
| --- | --- | --- | --- |
| deny | block | the deny rule | `denied by C` |
| ask | defer | the ask rule | `approval required by C` |
| confined | allow | the ask rule passed over | `confined by X, so R does not ask`, or `confined, so R does not ask` when the tool names nothing |
| allow | allow | the allow rule | `allowed by C` |
| default allow | allow | none | `allowed by default` |
| default deny | block | none | `no rule allows T: denied by default` |
| default ask | defer | none | `no rule allows T: approval required by default` |

### Confinement

A call **runs confined** when its tool says so for the call's
arguments, through agenttool RFC 0001's confined property, and names
what confines it, or names nothing. A call whose tool does not answer,
whose tool the harness could not resolve, or whose tool answers not
confined, is unconfined: the safe mistake is to ask. A tool's
annotations are never read as confinement, since a server's hints are
not the tool's own claim.

A confined call is not asked about by a bare ask rule, as both
reference agents skip a bare `Bash` ask for a sandboxed command. A deny
rule applies whatever the confinement. An ask rule with a specifier
applies too, which is how a policy still asks about a call that leaves
its sandbox, `bash(sandbox:escalated)` for a tool whose escape hatch
is an argument. The default applies as it does to any call no rule
names: a confined call to a tool no rule names still asks under an ask
default.

Confinement is the called tool's. A subject a splitter sends to
another tool's rules is decided unconfined.

A binding MAY let the host replace how confinement is read, or turn it
off, so every ask rule asks.

## Deciding a call

A call is decided in four steps.

1. **Split.** The call's subjects are its splitter's, or the call
   itself. A splitter that fails, or returns no subjects, blocks the
   call with no rule and the reason `N call could not be evaluated:
   E`, where `N` is the tool name and `E` the error, `splitter returned
   no subjects` for none.
2. **Fold the subjects.** Each subject is decided as the previous
   section says. The most restrictive verdict stands, block over defer
   over allow, and the first of equals. The verdict's subject is the
   text of the subject whose verdict stood. When a call split into
   more than one subject is blocked and the blocking subject has text,
   the reason continues ` on "S"; nothing in this command ran`, and
   then `, including ` and the texts of the other subjects, quoted,
   in order, leaving out empty texts, the blocking subject's own text
   and repeats, joined as prose, `"a"`, `"a" and "b"`, `"a", "b" and
   "c"`, so the model does not report the other half as having run.
   The `, including` clause is omitted when that leaves nothing. A
   quoted text is wrapped in `"`, with `"` and `\` escaped by a
   backslash; how other characters are escaped is open (see below).
3. **Fold the hooks.** A binding MAY take the host's own decision
   hooks and fold their decisions in, as [Hooks](#hooks) says.
4. **Hold.** A call the previous steps allow is held when another call
   of its batch asks, as [The batch hold](#the-batch-hold) says.

The decision the loop receives carries the verdict's action and
reason, and names the policy as its decider unless a hook that made
the action stricter named another. A block's reason is the text the
model reads as the call's output.

The same policy and the same call in the same batch MUST give the same
verdict, and deciding MUST NOT call a model or perform I/O beyond what
the host's matchers, splitters, hooks and tools do.

### Hooks

A host's own decision hooks belong inside the engine's decision rather
than chained after it: a hook chained after the engine is outside the
hold, so a call it defers lets its siblings run before anyone answers.
The fold is agentturn RFC 0001's chain fold, with the policy's verdict
first:

- the strictest action wins, block over defer over allow, and a block
  ends the fold;
- a hook that makes the action stricter brings its reason and its
  decider, `policy` when it names none, and the verdict then has no
  rule and no subject;
- the first note stands, and terminate is set when any hook sets it;
- arguments a hook rewrites pass to the hooks after it, are what the
  call runs with, and are decided again, their confinement read from
  them: the stricter of the two actions stands, a verdict the policy
  still owns takes the rewrite's rule and reason, and the verdict's
  confinement is the rewrite's;
- a hook's error fails the call's decision.

Since the engine decides a call's siblings to decide the hold, a hook
is called for a sibling before the loop hands it that sibling's own
call. A hook MUST decide a call the same way however often it is
asked, and a hook that fails for a sibling reads as asking.

### The batch hold

An ask holds its batch, so nothing the model asked for in the same turn
runs before the user has answered. A call whose decision is allow is
**held** when any other call of its batch, decided as the call itself
would be, policy and hooks, defers. A held call is deferred, with the
verdict's held flag set and the reason `held for approval: ` followed
by the reason it was allowed. A blocked call is blocked whatever its
batch holds, and a deferred call is deferred on its own account.

A sibling's confinement is read from its own tool when the harness has
handed the engine that sibling's call, and otherwise from the tool a
host-supplied lookup names for it, or read as unconfined when there is
none. So without a lookup, a call before a confined command that a
bare ask rule names is held for it. A reading only ever moves toward
asking within a batch: a sibling once read as asking stays so, and a
call decided twice is held at least as often as the first time, so it
never runs beside an ask.

A batch is identified by its run, its turn, every call's ID, name and
arguments, and the rules in force. A binding MAY cache the siblings'
readings for a batch, and MUST NOT read a cache across two batches or
across a change of rules.

The loop decides every call of a batch before any executes, under
agentturn RFC 0001, which is what lets the engine see an ask wherever
it sits in the batch.

## Offering tools

A deny rule that is bare, or whose tool name is a glob, denies every
call of the tools it names, and both reference agents answer that by
never offering the tool: the model does not see it, plans nothing
around it and spends no tokens being refused. A tool is **removed** by
the first such rule of the active deny list that names it and that no
carve-out of the list reaches: a carve-out whose tool name is the
rule's tool name, from a source that does not rank below the rule's.
Such a carve-out lets some calls through, so the rule no longer
denies every call; its pattern is matched only once a subject
arrives, so any such carve-out keeps the tool offered. A deny rule
with a specifier denies some calls and leaves the tool offered.

The removal test and the decision's tool-name test are one test, so a
front that lists what a policy withheld and the list the model is
offered cannot disagree. Removing a tool is not a verdict and is not
recorded: it answers what the model is offered, once per turn, not
what was decided about a call.

## Grants

The rules change under an engine in four ways. None of them edits a
decision already made: a run that ended on an ask is answered under the
rules that deferred it.

**Replace.** The host replaces the policy, validated as building
validates one and expanded through the same aliases. It is what a tool
list that changes needs: a tool a server announces mid-session is one
the policy never heard of, and an ask default parks an unattended run
on it. A host that cannot re-derive its policy covers the tools it has
not seen with a bare name or a tool-name glob in the deny or ask list.

**Grant.** An "always allow" answering a prompt the default raised
appends an allow rule, expanded through the aliases. A rule that could
not build as an allow rule, and a carve-out, is refused.

**Grant over.** An "always allow" answering a prompt an ask rule
raised must also keep that rule from firing, since precedence alone
would let it ask again. Given the verdict that deferred the call and
the rule to grant:

- when the verdict has no rule, the default asked, and the grant is a
  plain grant;
- a bare grant removes the ask rule from the ask list;
- a grant with a specifier appends the carve-out `T(!S)` to the ask
  list, under the grant's own source, so a host that persists its own
  source's rules writes a personal "always allow" into its own
  settings;
- either way the grant's rules are appended to the allow list.

It is refused, with stable text a front shows as it drops the
"always" option and offers a one-time approval instead:

| when | reason |
| --- | --- |
| the grant could not build as an allow rule, or is a carve-out | the build error's text |
| a deny rule produced the verdict | `cannot grant over a deny rule: R` |
| the verdict did not defer | `nothing to grant over: the call was not deferred` |
| the verdict was a hold | `nothing to grant over: the call was held for another call's approval` |
| no expansion of the grant has a tool name equal to the ask rule's, so a tool-name glob ask is never granted over | `grant G does not name the tool of R` |
| the ask rule's source outranks the grant's | `R from S outranks the grant`, or `R outranks the grant` for the host's own |
| the ask rule is no longer in the policy's ask list, which a grant set's ask rule never is | `R is no longer in the ask list` |

A grant never beats a deny.

### Grant sets

A skill's `allowed-tools` is a grant with no prompt behind it: there
is no verdict to grant over, and an appended allow rule loses to any
ask rule naming the tool. A **grant set** activates a rule set under
its source instead.

While a set is active, its allow rules **shadow** the ask rules they
cover: an ask rule is passed over for a subject when an active set,
from another source whose rank is at or above the ask rule's source's,
has an allow rule that fires for the subject within that set's allow
list. A set from the ask rule's own source shadows nothing, since a
set that both asks and allows for a subject means ask. The set's own
allow rules, appended to the active allow list, then decide the
subject.

Activating a set stamps each rule with the set's source, expands it
through the aliases, and keeps or refuses each:

| rule | refused when | reason |
| --- | --- | --- |
| deny, ask | it could not build in its list | the build error's text |
| allow | it could not build as an allow rule, or is a carve-out | the build error's text |
| allow | the source is untrusted | `withheld: the source N is not trusted` |
| allow | a bare deny rule of the policy that no carve-out reaches names its tool | `denied by R: a grant never beats a deny` |
| allow | a bare ask rule of the policy that no carve-out reaches, from a source that outranks the set, names its tool | `R from S outranks the grant`, or `R outranks the grant` |

Deny rules are considered first, then ask, then allow, each in order.
A set's deny and ask rules apply at once, trusted or not, since they
only restrict. An untrusted set's allow rules are withheld, reported
with the policy's withheld list, and never evaluated. An ask rule with
a specifier is not a reason to refuse: whether it fires is a question
about a subject, and shadowing answers it at the decision. Nor is a
bare rule a carve-out reaches, as the offer reads one: the carve-out
lets some subjects past it, and the decision tells which.

Sets are keyed by source name: activating a set under a name already
active replaces it in place, and **revoking** a name removes its set,
which is what a host does at the turn boundary for a grant that lasts
one turn. A set's bare deny, a skill's `disallowed-tools`, removes the
tool from the offer for as long as the set is active.

Every grant, every grant set's refusal, and every revocation that
removed a rule is a verdict: allow with the rule and `granted G` for a
grant, `granted G over R` for a grant over and `granted G by N` for a
grant set, `N` its source's name or `the product` when it has none;
block with the rule and `not granted G: reason` for a grant set's
refusal; block
with `revoked the rules granted by N` for a revocation. The decider is
`policy`.

## Deferred calls

A deferred call ends the run with the call pending, and the host
answers it through the loop's resume, under agentturn RFC 0001. The
engine remembers every call it deferred, asked and held, under the
call's own run, so one engine serves every agent of a host and a
decision in one run never touches another's. It forgets a call as it
answers it, and forgets a run on the host's word when the run ends
another way.

### Release

A held call's answer follows from the answers to the calls that asked.
Given a run's end and the host's answers to its asked calls, a release
returns one answer per pending call in the order the run's end lists
them, the model's order:

- a pending call the host answered keeps its answer;
- a held call is approved, with the arguments and the note the hooks
  gave it, unless any of the host's answers ends the run, in which case
  it is answered with the output `The call was held for an approval
  and the turn was stopped; the call did not run.`;
- an answer for a call that is not pending follows the rest;
- a pending call neither the host nor the engine answers is an error
  naming every such call, returned with the answers as a preview:
  nothing is forgotten and nothing is recorded, so the host answers
  the missing call and releases again.

Every answer the engine builds names `policy` as its decider. Every
release is a verdict with held set: allow with the rule that allowed
the call and `released: ` followed by the reason it was allowed, or
block with `not released: the turn was stopped`.

### Answers without a human

A **reviewer** answers a deferred call where a human would: a rule of
the host's, a model, or a front that asks a person. It receives the
call as the decision saw it and the verdict that deferred it, with
the arguments a hook rewrote the call to in place of the model's,
since those are what the verdict is about, and
answers with an outcome, **approved**, **refused** or **timed out**, a
reason, replacement arguments for an approval, a note for the model,
and who answered, `agent` when it says nothing.

Answering a run's pending calls with a reviewer, per pending call in
order:

- A held call is left to the release, which runs last.
- A call the loop never handed to its tool, pending as undispatched,
  was decided by nothing, and the loop puts an approval of it to its
  decision hook on resume as a run would. It is approved, by `policy`,
  with the reason `not started: decided on resume`, for the policy to
  decide there. This answer is no verdict: the decision on resume is,
  and one here would say allow for a call the policy may then block.
- A call the record says never started but that the loop lists under
  another reason is refused with `The call was cut off before it
  started; it did not run.` and the verdict `not run: the call never
  started`, since the loop would hold an approval of it to the replay
  rule and refuse it.
- A call the record says a decision refused before it ran, pending as
  rejected, is owed that refusal and nothing else. It is answered
  without the reviewer, by `policy`, with `The call was refused before
  it ran; it did not run.` and the verdict `not run: the call was
  refused before it ran`.
- A call the record shows completed elsewhere, on a branch a rebase
  left or in the session this one forks, is answered with that output,
  by `policy`, with the record's reason for where it ran, such as `ran
  on a branch the rebase left`, as the answer's reason and the
  verdict's, before the replay rule: it is owed that output and must
  not run again.
- A call that may have run, cut off by an abort or found unanswered in
  a seeded transcript, is not the reviewer's to approve. When its tool
  says a second run is safe, or safe under its first run's key and the
  loop carries that key, it is decided under the policy of the moment,
  with its tool's confinement and the hooks but no hold, since it may
  never have been decided at all. It is decided on the arguments it
  would run again with: those of the dispatch it repeats, which a
  decision may have rewritten, else the model's. When a hook rewrites
  them to other arguments, the verdict is about the rewrite; a
  rewrite whose tool does not say it is safe to run is refused with
  `The call was cut off before it finished and may have run; it was
  not run again.` and the verdict `not run again: a hook rewrote the
  arguments, and replay is X for the rewrite`, since a keyed call
  runs again only with the arguments of the dispatch it repeats.
  Otherwise: allowed, it is approved and runs
  again, with the verdict `run again: replay X; ` and the policy's
  reason; asked, it goes to the reviewer with that verdict and the
  arguments it is about; denied, it
  is refused with `The call was cut off before it finished and may
  have run; it was not run again.`, a space, and the refusal text
  below with the policy's reason and `W` as `policy`, the verdict's
  reason being the policy's own. A hook that fails reads as asking:
  the verdict defers, with no rule and the reason `N hook failed: E`,
  and goes to the reviewer. Otherwise it is refused
  with `The call was cut off before it finished and may have run; it
  was not run again.` and the verdict `not reviewed: ` and the pending
  reason. A call already answered is refused the same way.
- Every other call goes to the reviewer.

A reviewer's answer becomes:

| outcome | answer | verdict reason | decider |
| --- | --- | --- | --- |
| approved | approve, with the reviewer's arguments when given, else a hook's rewrite when there was one, and its note | `approved by reviewer`, `: reason` when given | the reviewer's |
| refused | the refusal text below, and its note; for a call that may have run, `The call was cut off before it finished and may have run; it was not run again.`, a space, and the refusal text | `denied by reviewer`, `: reason` when given | the reviewer's |
| timed out | `The reviewer did not answer in time; the call did not run.`; for a call that may have run, `The call was cut off before it finished and may have run; it was not run again. The reviewer did not answer in time.` | `reviewer timed out` | `policy` |
| the review failed | `The reviewer could not evaluate the call; the call did not run.`; for a call that may have run, `The call was cut off before it finished and may have run; it was not run again. The reviewer could not evaluate the call.` | `reviewer failed: E` | `policy` |

The refusal text is `Denied by W: reason. ` or `Denied by W. ` with no
reason, where `W` is `policy` when the reviewer names the policy as
its decider and `reviewer` otherwise, and the reason is trimmed of
surrounding whitespace and then of one trailing full stop, so the stop
is not doubled, followed by `Do not pursue the same outcome
through a workaround, indirect execution or policy circumvention.`
A call that may have run is one the policy asked about running again,
or one held after its dispatch that may run again. Every answer names
its decider; a refusal, a timeout and a failed review also carry the
verdict's reason, so the record's decision says why without the
verdict beside it. Every answer is a verdict: allow for an approval,
block otherwise.

An approval of a call that may have run whose arguments differ from
those the call would run with, a hook's rewrite when there was one,
else those of the dispatch it repeats, compared as values, is refused
with `The call was cut off before it finished and may have run; it was
not run again.`, by `policy`, with the verdict `not run again: the
reviewer rewrote the arguments, and replay is X for the rewrite`, `X`
being what the tool says of running the rewrite, unless its tool says
the rewrite is safe to run, since the loop runs a keyed call again only
with the arguments of the dispatch it repeats. It is not a refusal of
the reviewer's and does not count toward the bound.

A **denial bound** stops a reviewer that refuses and refuses: after a
number of consecutive refusals, or a number within a window of recent
reviews, every refusal among the answers ends the run, and the host is
told the bound was reached. Every answer that is not an approval
counts, a timeout and a failed review included; a call answered
without the reviewer does not, nor does the refusal of a reviewer's
rewrite above. The reference bound is three
consecutive, or ten within the last fifty. The count persists across
answers until the host resets it, which it does at each new user
message.

Answering completes with a release, so the held calls are answered
from the reviewer's answers.

## Guards

A guard checks content. Its **subject** is one of:

- an **input**: a request's input items as the loop built them, and
  its instructions, which is where most of what enters a window is:
  an AGENTS.md chain read out of a checkout, a skill catalogue, a
  memory block the model wrote;
- a **message**: one assistant message as the stream completes it,
  before the transcript, the record or the front keeps it;
- an **output**: a finished turn's response, its items already in the
  transcript, as the model produced it and not as the output guard's
  rewrites left it, and whether the turn is **final**, one in which
  the model called no tools, so the response is the run's answer. A
  guard over the answer passes a turn that is not final.

A guard answers with an action and a reason, and for an input or a
message MAY rewrite: replacement items for an input, a replacement
message for a message, replacement instructions for an input. Defer
has no meaning for content and is an error. A guard passes a subject
it does not know.

A **chain** runs guards in order, each seeing the subject as the one
before left it, and reports every guard's verdict exactly once per
check:

| hook | subject | allow | block | error or defer |
| --- | --- | --- | --- | --- |
| before model call | input | a rewrite replaces the request's input or instructions for this call | the run stops as a guard stop, before the model is called | the model call is blocked and the run fails |
| output guard | message | a rewrite replaces the message for the guards after and for the transcript | the message is withheld behind a placeholder built from the message as the guards before left it, or, when the chain stops on a block, withheld and the run stops as a guard stop; the guards after are not consulted | fails the run |
| should stop after turn | output | — | the run stops after the turn as a guard stop, and the guards after are not consulted | fails the run |

A guard's error that is a guard stop, one that wraps agentturn's guard
error, is not a failure on any hook: the run stops as a guard stop,
and the chain reports it as that guard's block, its reason the
reason the error carries, else the error's text, before it returns
the error.

A guard stop is agentturn RFC 0001's: the run ends stopped with cause
`guard`, and the error names the guard, the subject, `input`,
`message` or `output`, and the reason. On the output guard the loop
withholds the message, and neither it nor the reason reaches the
caller; the fronts report a content filter. The default placeholder
is an assistant message reading `Withheld by G: reason`, with the
identity, status and phase of the original, so a front's item end
matches its item start. Withholding behind a placeholder does not end
the run, and the caller reads the reason; a host that must not show
it stops the run instead.

Nothing in a guard chain calls a model. A guard backed by one is the
host's, through a binding's package: the reference asks for one JSON
object, `{"allow": true or false, "reason": "..."}`, reads the first
such object in the answer, and treats a model failure or an answer it
cannot read as an error, so the chain fails closed.

The reference guards, informative:

| guard | subjects | verdict |
| --- | --- | --- |
| `limit` | all | block when the byte length of the items' JSON encoding, plus the byte length of an input's instructions, is over a bound: `K is N bytes, over the M byte limit`, `K` being `input`, `message` or `output` |
| `deny` | all | block on the first pattern matching an input's instructions, or any text of the items: `matched denied pattern "P"` |
| `secrets` | all | block on the first secret shape found: `secret detected: NAME` |
| `redact` | input, message | rewrite every secret to `[REDACTED NAME]`: `redacted N secret: NAME` for one and `redacted N secrets: NAMES` for more, the distinct names in the order found joined by `, `; on an output, block as `secrets` does over the items that are not messages, since the messages were its to rewrite on the output guard and the output holds them as the model said them |

The text of an item is a message's text parts, a function call's
arguments, a function call output's text or text parts, and a
reasoning item's summary and content.

## The verdict

A verdict is what was decided and why:

| member | meaning |
| --- | --- |
| run, turn | the run and the turn it was decided in; empty for a grant, and the turn empty for an input guard's |
| call ID, tool | the call decided; a grant names the rule's tool; empty for content |
| guard | the guard that decided content; empty otherwise |
| action | allow, block or defer |
| rule | the rule that fired, the rule a confined call passed over, or the rule granted; none for the default, a hook's stricter action, a guard or a reviewer |
| reason | the stable text; for a block of a call, what the model reads |
| by | the decider: `policy`, `agent` or `human`; empty for a guard's, whose decider is the guard |
| held | set on a hold, and on the release or refusal that answers it |
| subject | the text of the subject whose verdict the fold kept; empty for a call no splitter split |
| confined | what confines the call, whatever the action; empty when unconfined or unnamed |

Every verdict reaches every observer the host registered, exactly
once, in the order they were registered, and outside any lock the
engine holds.

### The record

The loop's recorder writes the decision the hook returned as the
call's `decision` entry, under agentsession RFC 0001: block as
`reject` with the reason, defer as `hold`, with `by: policy`. The
answers a release or a reviewer builds name their decider, so the
`proceed`, `reject` or `answer` that follows says who answered.

What the decision entry cannot carry, the rule and its source, the
source's hash and the rule's note, a guard's verdict, a grant, what
confined a call, is written by the host beside it as a `custom` entry
with `ns` set to `agentpolicy:verdict` and `data` a JSON object:

| member | value |
| --- | --- |
| `run_id`, `turn`, `call_id`, `tool`, `guard` | as the verdict names them |
| `action` | `"allow"`, `"block"` or `"defer"`; always present |
| `rule` | the rule's string form |
| `source` | the rule's source's name |
| `source_hash` | the rule's source's hash, the digest of the settings file or the skill frontmatter the rule was read from, so a reader says which version of the source a decision or a grant was built from and not only its name |
| `note` | the rule's note, whatever its source |
| `reason`, `by`, `held`, `subject`, `confined` | as the verdict names them |

Every member but `action` is omitted when the verdict leaves it empty,
zero or false. A reader MUST ignore members it does not know.

## Presets

Three presets approximate Codex CLI's approval modes, over a host's
split of its tools into those that read, those that edit and those
that execute. They are worked examples of the grammar, informative:

| preset | allow | ask | default |
| --- | --- | --- | --- |
| suggest | read | edit, execute | ask |
| auto-edit | read, edit | execute | ask |
| full-auto | read, edit, execute | — | ask |

Every rule is bare. A confined call is therefore not asked about by
the ask rules, as the reference does not ask about a sandboxed
command; confinement is one bit, so under a sandbox that permits
writes, suggest allows every confined command auto-edit does. The
reference also confines each mode to a sandbox, which is the host's to
arrange.

## Bindings

### Go

The root module of this repository is the reference binding.

| Contract | Go |
| --- | --- |
| rule | `Rule{Tool, Spec, Source, Note}`; `String`, `Bare`, `Glob`, `MatchesTool`, `CarveOut` |
| grammar | `ParseRules(s)`; every error begins `agentpolicy: rule "<token>": ` and ends with the kind's text, `unbalanced parentheses`, `missing tool name`, `empty specifier`, `empty carve-out`, `text after the specifier` |
| source | `Source{Name, Path, Hash, Trusted, Rank}` |
| policy | `Policy{Allow, Deny, Ask, Default, Sources, Withheld}`; `Allow()`, `Deny()`, `Ask()`; the zero `Default` is unset |
| merge | `RuleSet{Source, Allow, Deny, Ask}`, `Merge(sets…)` |
| matcher | `Matcher func(spec, args) bool`; `PrefixMatcher(field)`, `GlobMatcher(field)` |
| splitter, subject | `Subjects func(args) ([]Subject, error)`, `Subject{Args, Tool, Text}`; `ToolMatcher{Match, Subjects}` per tool |
| aliases | `WithAliases(map[string][]string)` |
| build | `Build(policy, matchers, opts…)`; `ErrNoDefault`, `ErrNoMatcher`, `ErrToolGlob` for the kinds, and a plain error for `invalid_rule` |
| engine | `Engine`; `Policy`, `PolicyOf(source)`, `Sources`, `Withheld`, `SetPolicy` |
| decision | `Engine.Decide`, `Engine.BeforeToolCall()` for `agentturn.Config.BeforeToolCall` |
| confinement | `agenttool.ConfinedBy` by default; `WithConfinement(fn)`, `nil` to turn it off |
| sibling tools | `WithTools(lookup)` |
| hooks | `WithHooks(fns…)` |
| offering tools | `Engine.Removes(tool)`, `Engine.Filter(tools)`, `Engine.ToolProvider(base)` for `agentturn.Config.ToolProvider` |
| grants | `Engine.Grant`, `Engine.GrantOver`; `Engine.GrantSet` → granted and `[]Refusal{Rule, Reason}`, `Engine.Revoke`, `Engine.Grants` |
| deferred calls | `Engine.Deferred`, `Engine.Runs`, `Engine.Forget` |
| release | `Engine.Release(ctx, end, answers…)`; `ErrUnanswered` |
| reviewer | `Reviewer`, `ReviewerFunc`, `Review{Outcome, Reason, Args, Note, By}`, `Outcome` (`Refused`, `Approved`, `TimedOut`); `Engine.Answers(ctx, r, end)`, whose refusals carry the verdict's reason as `agentturn.Answer.Reason`; a call that may have run is `agentturn.PendingCall.MayHaveRun` |
| cut-off calls | `WithNeverStarted(fn)`, `WithRan(fn)`; the tool from the pending call or `WithTools`; `agentturn.PendingUndispatched` is approved for the resume, `agentturn.PendingRejected` answered as refused |
| denial bound | `DenialBound{Consecutive, Total, Window}`, `DefaultDenialBound`, `WithDenialBound`, `ErrDenialBound`, `Engine.ResetReviews` |
| decider | `ByPolicy`, `ByAgent`, `ByHuman` |
| verdict | `Verdict{RunID, Turn, CallID, Tool, Guard, Action, Rule, Reason, By, Held, Subject, Confined}`; `WithObserver(fn)`, which adds an observer |
| record | `VerdictNS = "agentpolicy:verdict"`; `Verdict.Record()` → namespace and bytes |
| presets | `Tools{Read, Edit, Execute}`; `Suggest`, `AutoEdit`, `FullAuto` |
| guard | `guard.Guard{Name, Check}`, `guard.New`; `guard.Input{Items, Instructions}`, `guard.Message`, `guard.Output`; `guard.Verdict{Action, Reason, Items, Instructions}` |
| chain | `guard.Chain{Guards, Observer, Placeholder, Stop}`; `BeforeModelCall`, `OutputGuard`, `ShouldStopAfterTurn`; `guard.Withheld` |
| guard stop | `guard.BlockedError{Guard, Subject, Reason}`, which wraps `agentturn.ErrGuard` |
| reference guards | `guard.Limit`, `guard.Deny`, `guard.Secrets`, `guard.Redact`, `guard.Pattern`, `guard.DefaultSecrets` |
| model-backed | `classify.New` for a guard, `classify.NewReviewer` for a reviewer |

Every error the root package makes begins with `agentpolicy:`, and
the guard and classify packages' with `agentpolicy/guard:` and
`agentpolicy/classify:`. Two are passed through as given: a hook's
error from `Decide`, and the context's error from `Answers`. The texts
the model reads, a reason and an answer's output, are not prefixed.

### agentskill

agentskill parses a skill's `allowed-tools` with the grammar, into
`ToolRule{Tool, Spec}`, which maps onto `Rule` field for field with no
import either way. A host activates a skill's rules as a grant set
under the skill's source, and revokes it at the turn boundary.

### agentturn

| hook | value |
| --- | --- |
| `BeforeToolCall` | `Engine.BeforeToolCall()` |
| `ToolProvider` | `Engine.ToolProvider(base)` |
| `BeforeModelCall` | `guard.Chain.BeforeModelCall()` |
| `OutputGuard` | `guard.Chain.OutputGuard()` |
| `ShouldStopAfterTurn` | `guard.Chain.ShouldStopAfterTurn()` |
| `Resume` | the answers of `Engine.Release` or `Engine.Answers` |

## Conformance

**A conforming parser** produces, for every case of
`testdata/policy/grammar.json`, the rules the case lists, or refuses
the input with the error kind and token the case names. agentskill's
parser is one.

**A conforming matcher** named prefix or glob answers every case of
`testdata/policy/matchers.json` for its name as the case says.

**A conforming engine** refuses a policy with no default, a rule that
could never fire and a tool-name glob it will not honour; decides
every subject by the precedence as an algorithm, whatever the order of
the lists; folds a call's subjects to the most restrictive; blocks a
call whose splitter fails; reads confinement from the called tool and
reads an unanswered tool as unconfined; holds every call it allows
when another of its batch asks, and never runs one beside an ask;
gives the reason texts this document states; reports every verdict to
every observer exactly once; remembers a deferred call under its own
run; answers a held call only from the answers to the asked ones; and
for every case of `testdata/policy/decisions.json` builds, grants,
decides and offers as the case says.

**A conforming guard chain** runs its guards in order over the subject
the one before left; never defers content; stops the run as a guard
stop on a blocked input or output and withholds a blocked message; and
reports every guard's verdict exactly once.

**A conforming recorder** writes a verdict under
`agentpolicy:verdict` in the shape [the record](#the-record) gives.

### The fixture corpus

`testdata/policy/` holds three JSON files. Each is an object with a
`cases` array; a member a case does not use is absent, and a harness
SHOULD refuse a member it does not know, so a fixture that names
something nothing checks fails loudly.

**`grammar.json`.** A case has `name`, `input`, and either `rules`, an
array of `{"tool", "spec"?}` in order, or `error`, `{"kind",
"token"}`.

**`matchers.json`.** A case has `matcher`, `"prefix"` or `"glob"`,
reading the member `command`; `spec`; either `args`, a JSON value, or
`raw`, arguments that are not JSON, the empty string included; and
`match`.

**`decisions.json`.** The top-level `matchers` is the default matcher
table, which a case's own `matchers` replaces. A matcher table maps a
tool name to `{"match", "field", "split"?}`, `match` naming a
reference matcher or absent for none, and `split` saying the tool has
a splitter. A case has:

- `name`;
- `aliases`, an alias table;
- `policy`: `sources`, merged as [Merge](#merge) says, each `{"name",
  "rank", "trusted", "allow"?, "deny"?, "ask"?, "notes"?}`, with lists
  written in the grammar and `notes` mapping a rule's string form to
  its note; then `allow`, `deny` and `ask`, the host's own rules,
  appended after the merged lists; and `default`, `"allow"`, `"deny"`,
  `"ask"` or absent for unset;
- `build_error`, the kind building MUST refuse with, in which case
  nothing else is checked;
- `grants`, activated in order as grant sets after building: `source`,
  `{"name", "rank", "trusted"}`; `allow`, `deny` and `ask` beside it,
  in the grammar, with no notes; `granted`, the rules kept as allow
  rules in string form; and `refused`, `{"rule", "reason"}` in order;
- `calls`, each decided as a batch of its own, the first in turn 1 and
  each after in the next; and `batch`, decided in order as one batch,
  in the turn after the last of `calls`. Call IDs are `call_1`,
  `call_2`, … in batch order, and every call is in run `run_1`;
- `offer`, `{"tools", "want"}`: the tools, in order, that remain when
  the removed ones are taken out.

A call has `tool` and `args`. The splitter and the confinement are the
host's, so the corpus writes out what they answer for the call:
`subjects`, an array of `{"args", "text"?, "tool"?}` the splitter
returns, one subject of the call's own arguments when absent;
`subjects_error`, the splitter's error text; and `confined`, present
when the tool says the call runs confined, with what confines it, `""`
for nothing named. The calls of one case have distinct arguments per
tool, so a harness can find a call's answers from what the splitter
and the tool are handed. The tool a harness offers the engine for a
sibling is the one it offers for the call.

`want` is the verdict: `action`, `"allow"`, `"block"` or `"defer"`;
`held`; `rule` in string form and `source`, its source's name; the
exact `reason`; `subject`; and `confined`. An absent member is empty.
The decision the loop receives carries the same action and reason and
the decider `policy`, and deciding the same call again gives the same
decision.

The reference binding's tests run all three files, and its own tables
for the grammar, the reference matchers and the precedence are those
files, so the corpus, this document and the binding are held to one
another.

## Versioning

This document is versioned with the Go module. A draft number changes
when a rule is added or changed, a reason text included, since the
model reads it; a rule's removal, or a change that makes a conforming
engine non-conforming, is a breaking change to the module and is
listed in the changelog as one.

## Prior art

- **Claude Code**'s permission rules are the grammar's source: `Bash`,
  `Bash(git status:*)`, allow, deny and ask lists with deny first,
  settings files from an organisation, a project and a user that merge
  rather than override, a trust prompt before a project's rules apply,
  and a skill's `allowed-tools` as rules active while the skill runs.
  The glob matcher is its documented Bash pattern table. Its
  documentation leaves case sensitivity and carve-out scope unstated;
  this document states both.
- **Codex CLI**'s approval modes, suggest, auto-edit and full-auto,
  are the presets, and its auto-review, a model that answers an
  approval with a bounded number of refusals, is the reviewer and the
  denial bound. Codex pairs each mode with a sandbox policy; this
  document reads a tool's confinement instead of owning one.
- **Cedar** and **OPA** are general policy languages. Cedar's rule that
  a `forbid` overrides any `permit` is the same shape as deny before
  allow; neither has an ask, a batch, or a notion of a grant that lasts
  as long as its source.
- **agentturn RFC 0001** defines the decision seam, the batch decided
  before any call runs, the pending call and the resume, the guard
  stop, and the chain fold the hooks follow.
- **agenttool RFC 0001** defines a tool's confined property and its
  replay property, which the engine reads.
- **agentsession RFC 0001** defines the `decision` entry and its
  deciders, and the `custom` entry a verdict is written as.

## Open questions

- **A grant set per run** (#18). One engine serves every agent of a
  host and remembers deferred calls per run, but a grant set has no
  run, so a skill the main agent opened grants its tools to a
  sub-agent that never opened it. Keying sets by run, or a scope on
  the set, are the options.
- **A context for the sibling lookup** (#43). The lookup that reads a
  sibling's confinement takes a tool name alone, so an engine shared
  by concurrent runs whose tool lists differ reads one list for all of
  them, and a batch hold can be defeated. A lookup given the decision's
  context is proposed.
- **Cut-off calls and the reviewer** (#51, #52, #53). The
  answers without a human are the least settled section. A reviewer's refusal,
  timeout or failure on a call that may have run tells the model it
  did not run (#51); a never-started call is refused where the loop
  would put it to the policy (#52); a call the record shows rejected
  goes to the reviewer, and an approval of it fails the resume (#53).
  Each fix changes text this document states.
- **Presets for an open tool set** (#16). Every preset's default is
  ask, so a host with MCP or plugin tools either prompts for all of
  them or overrides the default and loses the guard for tools added
  later. A preset that names known-safe tools beside the split is
  proposed.
- Answered in v0.0.11: `redact` reads only the items that are not
  messages over a finished turn, since the messages were its to
  rewrite on the output guard (#17); the output subject says whether
  the turn is final, and the chain's doc says the two output hooks see
  the same words (#20); the placeholder is built from the message as
  the guards before the blocking one left it (#22).
- **The reason in the placeholder** (#49). The default placeholder
  puts the guard's reason, a deny pattern, in the answer a caller
  receives, which is the rule a caller could phrase around. A chain
  that stops on a block keeps it from the caller; one that goes on
  still shows it.
- **Quoting a subject.** The fold's reason quotes a subject as the
  reference's `strconv.Quote` does, which escapes a control character
  as `\x01` and a non-printable one as `\u00a0`. That is neither JSON
  nor anything a second language has built in. Quoting as a JSON
  string without HTML escaping, which agrees for every printable text,
  is the likely rule for draft 0.2.
- **Grants in the corpus.** The corpus covers grant sets; a grant over
  a verdict, a release and the answers without a human are stateful
  across calls and are held only by the reference's tests. A scenario
  form, a sequence of steps each with its expected verdicts, is the
  likely shape for draft 0.2.
