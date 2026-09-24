// Copyright 2026 Netflix, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may not
// use this file except in compliance with the License. You may obtain a copy of
// the License at
//
//  http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
// License for the specific language governing permissions and limitations under
// the License.

package main

import (
	"bufio"
	"errors"
	"io/fs"
	"os"
	"strings"
)

// readIgnore reads the OSV ids listed in a govulncheck.ignore file at path.
// It reads only the lines that start with GO- and reads only one advisory
// per line.
func readIgnore(path string) (map[string]bool, error) {
	f, err := os.Open(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()

	ignore := map[string]bool{}
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if fields := strings.Fields(line); len(fields) == 1 && strings.HasPrefix(fields[0], "GO-") {
			ignore[fields[0]] = true
		}
	}

	return ignore, scanner.Err()
}
