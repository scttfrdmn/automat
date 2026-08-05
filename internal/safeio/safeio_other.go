// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

//go:build !unix

package safeio

import "io/fs"

// OpenNonBlock has no equivalent outside unix, where the FIFO problem it addresses
// also does not arise.
const OpenNonBlock = 0

// OwnerUID reports that this platform does not express ownership as a uid.
//
// Returning false rather than a fabricated value means the owner check is skipped
// rather than made against a number that means nothing. The other defenses — the
// mode check, the symlink refusal, and the SameFile identity comparison — do not
// depend on it.
func OwnerUID(fs.FileInfo) (uint32, bool) { return 0, false }

// LinkCount reports that this platform does not say.
//
// Skipping the hardlink check here is the right trade: it defends against a local
// attacker who already needs write access to the directory, and every other check
// still applies. Failing every write on a platform that cannot answer would be a
// worse outcome than not making this one check.
func LinkCount(fs.FileInfo) (uint64, bool) { return 0, false }
