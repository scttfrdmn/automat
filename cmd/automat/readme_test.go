// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// The README makes claims about which commands exist. Those claims are checked
// against the command tree rather than against the ROADMAP, because the ROADMAP
// says what should be true and the tree says what is.
//
// This is the same discipline as internal/bundle's
// TestREADMEDisclosesWhatTheDelegateCanDoToAutomatsOwnControls, which asserts the
// bundle's cover note names `automat verify` AND says it does not ship yet — keyed
// to the actions the policy actually grants, so removing a grant retires the
// disclosure automatically. Here the key is the registered command set: a command
// that ships retires its "not in this version" entry, and a command claimed as
// working must actually be registered.
//
// Why it is worth a test at all: a README is the one document read by someone who
// has not run the tool, so it is the document where a claim outrunning the code
// does the most damage and is the least likely to be noticed. It is also the
// document that rots first, because shipping a command feels finished before the
// README is touched.

const readmePath = "../../README.md"

func readREADME(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(readmePath)
	if err != nil {
		t.Fatalf("read %s: %v", readmePath, err)
	}
	// Whitespace-normalized: the README is hard-wrapped prose and a phrase this
	// test looks for can straddle a line break. Pinning the wrap point would make
	// an editorial reflow fail a test about honesty, for no reason.
	return strings.Join(strings.Fields(string(data)), " ")
}

// registeredCommands returns every command name the built CLI actually offers,
// including cobra's own.
func registeredCommands(t *testing.T) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	var walk func(*cobra.Command)
	walk = func(c *cobra.Command) {
		for _, sub := range c.Commands() {
			out[sub.Name()] = true
			walk(sub)
		}
	}
	walk(newRootCmd())
	if len(out) == 0 {
		t.Fatal("the command tree is empty; this test would assert nothing")
	}
	return out
}

// TestREADMEClaimsOnlyCommandsThatExist is the positive half: every command the
// README presents as working must be registered.
func TestREADMEClaimsOnlyCommandsThatExist(t *testing.T) {
	s := readREADME(t)
	have := registeredCommands(t)

	// The commands the README's "What works today" table presents as usable. Listed
	// here rather than parsed out of the table because a parser that failed to find
	// a row would silently assert nothing, which is the failure mode this whole
	// file exists to prevent.
	claimed := []string{"preflight", "init", "setup", "login", "version"}

	for _, name := range claimed {
		if !strings.Contains(s, "`automat "+name+"`") {
			t.Errorf("this test expects the README to present `automat %s` as working, and it "+
				"does not appear. Either the README changed or this list is stale — fix "+
				"whichever is wrong rather than deleting the entry.", name)
			continue
		}
		if !have[name] {
			t.Errorf("the README presents `automat %s` as working, but no such command is "+
				"registered. A README claim that outruns the code is read by exactly the "+
				"person who cannot check it.", name)
		}
	}
}

// TestREADMEDoesNotPresentUnbuiltCommandsAsWorking is the half that matters more.
//
// Every command in DESIGN §13 that is not yet registered must appear in the
// README's "Not in this version" section — and the section is found by that exact
// phrase, the same marker internal/bundle's escalation test asserts in the cover
// note. Naming a command without saying it does not exist is the worse of the two
// failures: it invites someone to plan around a capability, or to approve a
// delegation on the strength of a check they cannot run.
func TestREADMEDoesNotPresentUnbuiltCommandsAsWorking(t *testing.T) {
	data, err := os.ReadFile(readmePath)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	full := string(data)
	have := registeredCommands(t)

	const marker = "## Not in this version"
	idx := strings.Index(full, marker)
	if idx < 0 {
		t.Fatalf("the README has no %q section. The section is the mechanism: without it "+
			"an unbuilt command named anywhere in the file reads as a feature.", marker)
	}
	// Two regions, because the disclosure only disclaims what comes after it. A
	// command named ABOVE the marker is presented as working no matter what the
	// section below says — and a reader who stops at the table (most readers) never
	// reaches the correction. The first version of this test checked only `after`,
	// and a jam check that added `automat vend` to the working table passed: the
	// entry below made it look disclosed. Naming a command in both places is the
	// most likely way for this file to go wrong, since shipping-adjacent work adds
	// the row and forgets the removal.
	norm := func(s string) string { return strings.Join(strings.Fields(s), " ") }
	before, after := norm(full[:idx]), norm(full[idx:])

	// DESIGN §13's command list, per docs/cli-surface.md, plus `assess` from the
	// scope approved in docs/assessment-reporting.md. `setup` is registered but only
	// its --request half works, so it is deliberately in both places; that is a
	// claim about a flag, not a command, and the README says which half.
	designCommands := []string{"init", "vend", "compile", "verify", "list", "reclaim", "assess"}

	for _, name := range designCommands {
		if have[name] {
			// Shipped. The disclosure requirement retires itself, and a stale entry
			// is now its own inaccuracy in the other direction.
			if strings.Contains(after, "`automat "+name+"`") {
				t.Errorf("`automat %s` is registered but still listed under %q — the README "+
					"now understates what the tool does, which is the same defect pointing "+
					"the other way", name, marker)
			}
			continue
		}
		if strings.Contains(before, "`automat "+name+"`") {
			t.Errorf("`automat %s` is not registered, but the README names it ABOVE the %q "+
				"heading — where it reads as working. The entry below does not fix this: a "+
				"reader who stops at the table never reaches the correction.", name, marker)
		}
		if !strings.Contains(after, "`automat "+name+"`") {
			t.Errorf("`automat %s` is in DESIGN §13 and is not registered, and the README's "+
				"%q section does not name it. Either it is absent from the README entirely "+
				"(acceptable) or it is described somewhere as though it works (not) — this "+
				"test cannot tell those apart, so the section must name it.", name, marker)
		}
	}
}

// TestREADMESaysVerifyDoesNotShipYet singles out the one unbuilt command with a
// security consequence.
//
// The delegation automat asks for grants organizations:DetachPolicy on automat's
// own policies, so the controls a vended account is born with are not permanent
// against the account that vended it. `automat verify` is the answer to that, and
// it does not exist. internal/bundle asserts the same pair in the cover note the
// approver reads; this asserts it in the file the approver's colleague reads
// first, because the README is where someone decides whether this tool is what
// they think it is.
func TestREADMESaysVerifyDoesNotShipYet(t *testing.T) {
	if registeredCommands(t)["verify"] {
		t.Skip("verify now ships; this test's premise is retired and it should be deleted " +
			"along with the README's disclosure")
	}
	s := readREADME(t)

	if !strings.Contains(s, "not permanent") {
		t.Error("the README does not say the controls a vended account is born with are " +
			"not permanent against the account that vended it. The delegation grants " +
			"DetachPolicy, so a reader who takes 'born compliant' as a guarantee has read " +
			"something that is not true.")
	}
	if !strings.Contains(s, "`automat verify`") {
		t.Error("the README states the problem without naming the remedy (`automat verify`)")
	}
	if !strings.Contains(s, "Not in this version") {
		t.Error("the README offers `automat verify` as the remedy without a " +
			"'Not in this version' section saying it does not ship yet")
	}
}

// TestREADMEDoesNotClaimSmokeTestsRunInCI guards the other claim a reader could
// take the wrong way. CLAUDE.md rule 1 is that nothing in tests or CI touches real
// AWS; `make smoke` is the manual opt-in exception. A README that mentioned smoke
// testing without that distinction would leave a reader believing the fake-backed
// guarantee is weaker than it is, or that the live path runs on its own.
func TestREADMEDoesNotClaimSmokeTestsRunInCI(t *testing.T) {
	s := readREADME(t)
	if !strings.Contains(s, "No test or CI run touches real AWS") {
		t.Error("the README does not state that no test or CI run touches real AWS; " +
			"that is CLAUDE.md rule 1 and the reason the fake-backed suite is worth trusting")
	}
	if strings.Contains(s, "make smoke") &&
		!strings.Contains(s, "manual") && !strings.Contains(s, "opt-in") {
		t.Error("the README names `make smoke` without marking it manual/opt-in, so it reads " +
			"as part of the ordinary build")
	}
}
