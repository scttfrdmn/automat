// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

//go:build !unix

package evidence

import "errors"

func mkfifo(string, uint32) error { return errors.New("no FIFOs on this platform") }
