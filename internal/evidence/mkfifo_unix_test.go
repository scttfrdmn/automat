// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package evidence

import "syscall"

// mkfifo creates a named pipe, so the FIFO test can state its intent once and skip
// on a platform that has none. syscall.Mkfifo does not exist on Windows, and a
// runtime GOOS check does not help: the reference still has to compile.
func mkfifo(path string, mode uint32) error { return syscall.Mkfifo(path, mode) }
