// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package safeio

import (
	"io/fs"
	"syscall"
)

// OpenNonBlock keeps a FIFO from blocking the open, in either direction. See the
// package comment: a mode-0600 FIFO the operator owns passes every permission
// check, and opening one blocks until the other end appears — for reading until a
// writer arrives, for writing until a reader does. Either way automat hangs with no
// output. Exported because internal/login needs it on a write path.
//
// On a regular file it is a no-op, which is all these opens are meant to reach.
const OpenNonBlock = syscall.O_NONBLOCK

// OwnerUID reports the uid owning the file, and whether the platform said.
func OwnerUID(fi fs.FileInfo) (uint32, bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return st.Uid, true
}

// LinkCount reports how many names refer to this file, and whether the platform
// said.
//
// A hardlink is a regular file by every mode check, and Lstat cannot tell one from
// an ordinary file: only the link count distinguishes them. Writing through one
// truncates whatever else shares the inode and copies the secret into it.
func LinkCount(fi fs.FileInfo) (uint64, bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return uint64(st.Nlink), true
}
