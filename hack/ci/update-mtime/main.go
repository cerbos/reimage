// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"bytes"
	"log"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var fnMatch = regexp.MustCompile(`^(go.sum|go.mod|(pkg|cmd|generated|oxi)/)`)

func main() {
	// We use a 4 byte abbreviation of the file content as this gives us
	// 32 bits, which maps to the mtime granularity of classic ext3.
	// Collisions between 4 and 8 bytes are no different at the time of testing.

	gitArgs := []string{
		`ls-tree`,
		`-r`,
		`--format=%(objectname) %(path)`,
		`--full-tree`,
		`--abbrev=4`,
		`HEAD`,
	}

	cmd := exec.Command(`git`, gitArgs...)

	outStr, err := cmd.Output()
	if err != nil {
		log.Fatalf("exec git failed, %v", err)
	}

	count := 0
	scanner := bufio.NewScanner(bytes.NewBuffer(outStr))
	for scanner.Scan() {
		l := scanner.Text()
		hash, fn, found := strings.Cut(l, " ")
		if !found {
			log.Printf("malformed input line, no separator: %q", l)
			continue
		}

		if !fnMatch.MatchString(fn) {
			continue
		}
		// We'll skip files that are unlikely to contribute to the Go test cache,
		// incase there is an impact on other tooling
		switch {
		case strings.HasSuffix(fn, ".go"):
		case strings.Contains(fn, "testdata"):
		case fn == "go.mod":
		case fn == "go.sum":
		default:
			continue
		}
		count++

		tInt, err := strconv.ParseInt(hash, 16, 64)
		if err != nil {
			log.Printf("could not parse %q, %v", l, err)
			continue
		}
		if tInt < 0 {
			tInt *= -1
		}

		t := time.Unix(tInt, 0)

		if err := os.Chtimes(fn, time.Unix(0, 0), t); err != nil {
			log.Printf("error updating times for %s, %v", fn, err)
		}
		// fmt.Printf("update mtime for %v to %v\n", fn, t.Unix())
	}

	log.Printf("updated %d file mtimes\n", count)

	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}
}
