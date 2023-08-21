// Copyright 2021-2023 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package main

import "fmt"

var (
	Version   = "unknown"
	Commit    = "dev"
	BuildDate = "unknown"
)

func printVersion() {
	fmt.Printf("%s (%s) built on %s\n", Version, Commit, BuildDate)
}
