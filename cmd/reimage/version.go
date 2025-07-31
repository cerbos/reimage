// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package main

import "fmt"

var (
	// Version is shown when printing the binary version.
	Version = "unknown"
	// Commit is shown when printing the binary version.
	Commit = "dev"
	// BuildDate is shown when printing the binary version.
	BuildDate = "unknown"
)

func versionStr() string {
	return fmt.Sprintf("%s (%s) built on %s", Version, Commit, BuildDate)
}
