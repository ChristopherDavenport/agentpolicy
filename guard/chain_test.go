package guard

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ChristopherDavenport/agentturn"
	"github.com/ChristopherDavenport/openresponses"
)

// A chain scoped to the first turn checks the input on the first model
// call of a run, as the turn the loop puts on the hook's context says,
// and not in a run a handoff started: two judges over a ten-turn run
// make two judge calls, where every turn would make twenty.
func TestChainFirstTurnScope(t *testing.T) {
	var mu sync.Mutex
	judged := 0
	judge := func(name string) Guard {
		return ReadOnly(New(name, func(context.Context, any) (Verdict, error) {
			mu.Lock()
			judged++
			mu.Unlock()
			return allow, nil
		}))
	}
	j := &journal{}
	hook := Chain{Guards: []Guard{judge("homework"), judge("injection")}, Observer: j.observe, Scope: FirstTurn}.BeforeModelCall()
	run := agentturn.ContextWithRunID(context.Background(), "run_1")
	for turn := 1; turn <= 10; turn++ {
		req := &openresponses.Request{Input: openresponses.Items{openresponses.UserText("hi")}}
		if err := hook(agentturn.ContextWithTurn(run, turn), req); err != nil {
			t.Fatal(err)
		}
	}
	if judged != 2 || len(j.all()) != 2 {
		t.Errorf("a ten-turn run made %d judge calls and %d verdicts, want 2", judged, len(j.all()))
	}
	handedOff := agentturn.ContextWithTrigger(agentturn.ContextWithTurn(run, 1), agentturn.Trigger{Kind: "handoff", Ref: "triage"})
	if err := hook(handedOff, &openresponses.Request{Input: openresponses.Items{openresponses.UserText("hi")}}); err != nil || judged != 2 {
		t.Errorf("a run a handoff started was checked: %d judge calls, %v", judged, err)
	}
	// Every call is the default.
	judged = 0
	every := Chain{Guards: []Guard{judge("homework")}}.BeforeModelCall()
	for turn := 1; turn <= 3; turn++ {
		_ = every(agentturn.ContextWithTurn(run, turn), &openresponses.Request{})
	}
	if judged != 3 {
		t.Errorf("an unscoped chain judged %d of 3 turns", judged)
	}
}

// meet is a pair of guards that each wait inside their check until the
// other has entered, so they pass only when they run at the same time.
func meet(names ...string) []Guard {
	var wg sync.WaitGroup
	wg.Add(len(names))
	out := make([]Guard, len(names))
	for i, name := range names {
		out[i] = ReadOnly(New(name, func(ctx context.Context, _ any) (Verdict, error) {
			wg.Done()
			met := make(chan struct{})
			go func() { wg.Wait(); close(met) }()
			select {
			case <-met:
				return allow, nil
			case <-time.After(2 * time.Second):
				return Verdict{}, errors.New("checked alone")
			case <-ctx.Done():
				return Verdict{}, ctx.Err()
			}
		}))
	}
	return out
}

// A parallel chain checks the guards that do not rewrite at the same
// time, and reports what checking them in order reports: the first
// block in chain order stands, the guards after it are not reported,
// and one still running is cancelled.
func TestChainParallel(t *testing.T) {
	ctx := agentturn.ContextWithRunID(context.Background(), "run_1")
	input := func() *openresponses.Request {
		return &openresponses.Request{Input: openresponses.Items{openresponses.UserText("my key is AKIAIOSFODNN7EXAMPLE")}}
	}

	t.Run("two judges meet inside the check", func(t *testing.T) {
		j := &journal{}
		if err := (Chain{Guards: meet("a", "b"), Observer: j.observe, Parallel: true}).BeforeModelCall()(ctx, input()); err != nil {
			t.Fatal(err)
		}
		if len(j.all()) != 2 {
			t.Errorf("verdicts = %+v", j.all())
		}
	})

	t.Run("a block reports what in order reports", func(t *testing.T) {
		cancelled := make(chan bool, 1)
		slow := ReadOnly(New("slow", func(ctx context.Context, _ any) (Verdict, error) {
			select {
			case <-ctx.Done():
				cancelled <- true
				return Verdict{}, ctx.Err()
			case <-time.After(2 * time.Second):
				cancelled <- false
				return block("too late"), nil
			}
		}))
		late := ReadOnly(New("late", func(context.Context, any) (Verdict, error) { return block("later"), nil }))
		guards := func(last Guard) []Guard {
			return []Guard{ReadOnly(fixed("a", allow, nil)), ReadOnly(fixed("b", block("bad"), nil)), last}
		}
		var reports []string
		for _, parallel := range []bool{false, true} {
			j := &journal{}
			err := Chain{Guards: guards(late), Observer: j.observe, Parallel: parallel}.BeforeModelCall()(ctx, input())
			var parts []string
			for _, v := range j.all() {
				parts = append(parts, fmt.Sprintf("%s %v %s", v.Guard, v.Action, v.Reason))
			}
			reports = append(reports, fmt.Sprintf("%v | %s", err, strings.Join(parts, ", ")))
		}
		if reports[0] != reports[1] {
			t.Errorf("in order: %s\nparallel: %s", reports[0], reports[1])
		}
		if want := "agentpolicy/guard: b blocked the input: bad | a 0 , b 1 bad"; reports[1] != want {
			t.Errorf("parallel: %s\nwant %s", reports[1], want)
		}
		if err := (Chain{Guards: guards(slow), Parallel: true}).BeforeModelCall()(ctx, input()); err == nil {
			t.Fatal("no block")
		}
		select {
		case c := <-cancelled:
			if !c {
				t.Error("the guard after the block was not cancelled")
			}
		case <-time.After(3 * time.Second):
			t.Error("the guard after the block never returned")
		}
	})

	t.Run("a guard that rewrites is checked in sequence", func(t *testing.T) {
		var saw []string
		var mu sync.Mutex
		look := ReadOnly(New("look", func(_ context.Context, subject any) (Verdict, error) {
			mu.Lock()
			defer mu.Unlock()
			saw = append(saw, subject.(Input).Items[0].(*openresponses.Message).Text())
			return allow, nil
		}))
		req := input()
		if err := (Chain{Guards: []Guard{Redact(), look}, Parallel: true}).BeforeModelCall()(ctx, req); err != nil {
			t.Fatal(err)
		}
		if len(saw) != 1 || saw[0] != "my key is [REDACTED aws_access_key]" {
			t.Errorf("the guard after the rewrite saw %q", saw)
		}
	})

	t.Run("a guard checked beside others may not rewrite", func(t *testing.T) {
		liar := ReadOnly(fixed("liar", Verdict{Action: agentturn.Allow, Items: openresponses.Items{openresponses.UserText("x")}}, nil))
		err := Chain{Guards: []Guard{liar, ReadOnly(fixed("b", allow, nil))}, Parallel: true}.BeforeModelCall()(ctx, input())
		if err == nil || err.Error() != "agentpolicy/guard: liar: rewrote a subject it was checked on beside other guards" {
			t.Errorf("err = %v", err)
		}
	})

	t.Run("the reference guards say they do not rewrite", func(t *testing.T) {
		for _, g := range []Guard{Limit(1), Deny(), Secrets()} {
			if r, ok := g.(Rewriting); !ok || r.Rewrites() {
				t.Errorf("%s does not say it reads only", g.Name())
			}
		}
		if r, ok := Redact().(Rewriting); !ok || !r.Rewrites() {
			t.Error("redact does not say it rewrites")
		}
	})
}

// An input guard's verdict names the turn whose model call it checked,
// as the loop puts it on the hook's context, its block and its failure
// included.
func TestAnInputVerdictNamesItsTurn(t *testing.T) {
	ctx := agentturn.ContextWithTurn(agentturn.ContextWithRunID(context.Background(), "run_1"), 3)
	j := &journal{}
	err := Chain{Guards: []Guard{fixed("a", allow, nil), fixed("b", block("bad"), nil)}, Observer: j.observe}.BeforeModelCall()(ctx, &openresponses.Request{})
	if !errors.Is(err, agentturn.ErrGuard) {
		t.Fatalf("err = %v", err)
	}
	failing := fixed("c", allow, fmt.Errorf("%w: spent", agentturn.ErrGuard))
	_ = Chain{Guards: []Guard{failing}, Observer: j.observe}.BeforeModelCall()(ctx, &openresponses.Request{})
	vs := j.all()
	if len(vs) != 3 {
		t.Fatalf("verdicts = %+v", vs)
	}
	for _, v := range vs {
		if v.RunID != "run_1" || v.Turn != 3 {
			t.Errorf("verdict = %+v, want run_1 turn 3", v)
		}
	}
}
