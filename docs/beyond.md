# Beyond this build

**automat is complete for its stated scope.** This page is the one forward pointer
DESIGN §15's branding rule permits, and it earns that permission by staying
capability-phrased throughout: what a future build could do, described by the gap it would
close, never by naming what anyone else already does. No commercial suite, company, or
upstream product is named here or anywhere else in this project.

## What this build covers today

A standalone or organization-owning account can vend member accounts with preventive
controls (service control policies) attached before anyone touches the account, re-check
those controls and a profile's freshness date, render a CMMC Level 1 self-assessment
summary from an operator's own determinations, and close an account it vended. Every
mutating step writes a hash-chained, optionally KMS-signed evidence record. Nothing here
watches an account continuously, and nothing here decides compliance on an operator's
behalf — see README's feature table and `docs/cli-surface.md` for exactly what ships.

## Capability gaps a later build could close

- **In-child baseline work** — the detective half of what a vended account needs: a
  Config recorder and delivery channel, a conformance pack compiled from the same control
  sets that produced the preventive layer, opt-in region enablement, attestation stubs for
  procedural controls, and an in-account automation role. Today's build attaches
  preventive controls only; nothing watches a vended account after it is created. This is
  the single largest gap between what ships and what DESIGN describes.
- **The remaining assessment stages** — the 800-171A objective worksheet and DFARS score
  arithmetic (Stages 1–2 of `docs/assessment-reporting.md`), gated on a weight table that
  needs independent double-transcription from a primary source before any code can consume
  it. Stage 3, the CMMC L1 summary, ships today.
- **Reading the remote evidence mirror back** — DESIGN §11 describes a second copy of the
  evidence chain (an object store, a management-side mirror) as the compensating control
  against a rewritten local manifest. The write half ships: every evidence-writing command
  uploads the local manifest's own bytes to a bucket named in the environment profile, once
  the local copy has already been written. What is still missing is the other half of the
  compensating control — `verify` fetching the mirrored copy and comparing it against the
  local file, flagging drift between the two as a new finding class. Until that exists, a
  rewritten local manifest and its now-stale mirror are two documents nothing in this
  codebase compares for you.
- **Signature verification and any form of trust registry** (DESIGN §11a). The KMS and
  local-key signers this build ships *produce* a signature; nothing in this codebase
  *checks* one, and there is no trust-policy loader and no registry of accepted signers.
  The intended mechanism for a later build is keyless identity-based signing distributed
  over an ordinary version-control host or artifact registry, so an institution adopting
  it never has to run a key ceremony of its own — automat would propose a format, not
  operate a service, and must never become a registry, a signing authority, or a
  standards body.
- **Additional catalogs** — HIPAA and NIST SP 800-53 baselines, data-only additions to the
  same compiled-artifact pipeline every shipped catalog already goes through. Blocked on
  choosing which published crosswalk a HIPAA catalog should compile against, not on any
  code change.
- **An approval queue** — this build is standing-delegation only: once a grant is approved,
  vending needs no further human step. A request/approve workflow for organizations that
  require one is out of scope for this build and would be additive, not a replacement.

## What stays out of scope regardless of build

Continuous monitoring, a dashboard, or an agent that runs unattended — this project's own
argument for why a point-in-time tool is the right shape does not change with more code.
A registry of trusted signers or accepted institutional policies — the reasoning above
applies permanently, not just until v2. And, unconditionally, no reference to any
commercial product anywhere this project's output reaches an operator's screen.
