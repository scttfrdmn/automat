// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

// Package evidence writes and checks the hash-chained evidence manifest: the
// chain of custody behind automat's "born compliant" claim (DESIGN §11).
//
// Its role in the vend pipeline is step 6, and it is the only step whose output
// outlives the vend. Every mutating operation appends a record naming the
// operator, the operation, the target, the control artifact by content hash, the
// environment profile by content hash, and what was actually attached. `verify` reads
// the chain back later and asks whether reality still matches it.
//
// # What the chain is for, stated narrowly
//
// It answers one question: "were these operations recorded as a sequence, and has
// the record of them been edited since?" It does not answer "is this account
// compliant" — that is `verify` against live AWS — and it does not answer "did
// these operations happen", because a record is automat's own claim about its own
// behaviour. What the chain adds over a log file is that the claims are *bound
// together*: changing record N invalidates every record after it.
//
// # Order comes from the links, not from the timestamps
//
// Each record carries the previous record's hash, and its own position. That is
// the ordering. The timestamps are claims *inside* the ordering, and nothing here
// derives sequence from them or refuses a record because a clock stepped
// backwards between two vends — an NTP correction is not tampering, and a
// validator that treated it as such would make archived manifests unreadable for
// a reason unrelated to their integrity.
//
// # What a hash chain does not protect, said plainly
//
// A chain detects edits to any record except the last, and detects truncation
// only because of the terminal record (below). Someone who can rewrite the file
// can drop records from the end and rewrite the tail consistently; the result is
// a shorter, internally valid chain. Signatures narrow that to someone who also
// holds the signing key, and an external anchor (a copy in the vended account's
// S3 bucket, a management-side mirror — DESIGN §11) narrows it further, because
// two chains that disagree about their own length are noticeable. None of that is
// in this package: what is here is the local copy and the invariants over it.
//
// # The terminal record, and why the Go side has to enforce half of it
//
// A chain may end deliberately, with a custody-transfer record: the account is
// handed to central IT, the grant is revoked, the project ends. Without it, every
// chain that stops looks exactly like one that was truncated, so no ending could
// be trusted and the whole format would be weaker. The published schema can say
// "at most one custody-transfer record"; it cannot say that record is the *last*
// one, because JSON Schema cannot refer to an array's final position. So
// terminality is enforced here, in VerifyChain and in Append, and
// artifact.TestTheSchemaCannotSayCustodyTransferIsLast is the pin that keeps this
// obligation from being quietly dropped.
//
// # Canonicalization is shared, deliberately
//
// Record hashes go through artifact.CanonicalJSON — the same function that hashes
// a control artifact's controls[]. One canonicalization, because a record must
// hash identically when it is written and when it is read back off disk years
// later, and two implementations of "canonical" is how that stops being true.
//
// Hashing is defined over the record's *meaning*, not its bytes: canonicalize
// fills the `outcome` default and normalizes empty collections before hashing, so
// a record that omits `outcome` and one that spells out `"success"` hash the same.
// A byte-level hash would make two documents that say the same thing verify
// differently, which is the ambiguity that makes a hash worthless as evidence.
//
// # Provenance only
//
// A record's environment-profile reference carries the attestations over that
// document which
// automat *verified* — never the ones merely present in the file. In v1 automat
// verifies nothing and records the empty set, and Append refuses a record that
// claims otherwise (DESIGN §11a). The manifest's own `signature` block is a
// different thing entirely: that is automat signing its own record with the
// operator's key, and it says nothing about any profile of any kind.
package evidence
