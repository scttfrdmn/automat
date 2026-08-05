// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

//go:build !unix

package config

import "errors"

// mkfifo is the stand-in on a platform without named pipes; the caller skips.
func mkfifo(string, uint32) error { return errors.New("no FIFOs on this platform") }
