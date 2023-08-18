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
