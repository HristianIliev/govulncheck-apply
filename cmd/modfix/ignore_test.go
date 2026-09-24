// Copyright 2026 Netflix, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestReadIgnore(t *testing.T) {
	for _, tt := range []struct {
		name    string
		content string
		want    map[string]bool
	}{
		{
			name: "ids, comments and blank lines",
			content: "# ignore these\nGO-2025-0001\n\nGO-2025-0002 # trailing comments are not stripped\n" +
				"  GO-2025-0003  \nnot-an-osv-id\n",
			// A line is only read as an id when it is a GO- id on its own, so the
			// trailing-comment and non-GO- lines are dropped rather than half-read.
			want: map[string]bool{"GO-2025-0001": true, "GO-2025-0003": true},
		},
		{
			name:    "empty file ignores nothing",
			content: "",
			want:    map[string]bool{},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "govulncheck.ignore")
			if err := os.WriteFile(path, []byte(tt.content), 0o644); err != nil {
				t.Fatal(err)
			}
			got, err := readIgnore(path)
			if err != nil {
				t.Fatalf("readIgnore(%q) failed: %v", path, err)
			}
			if diff := cmp.Diff(got, tt.want); diff != "" {
				t.Errorf("readIgnore(%q) differs (-got +want):\n%s", path, diff)
			}
		})
	}
}

func TestReadIgnoreMissingFile(t *testing.T) {
	got, err := readIgnore(filepath.Join(t.TempDir(), "govulncheck.ignore"))
	if err != nil {
		t.Fatalf("readIgnore() of a missing file failed: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("readIgnore() of a missing file = %v, want nothing to ignore", got)
	}
}
