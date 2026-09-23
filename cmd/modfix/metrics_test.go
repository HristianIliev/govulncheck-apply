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
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestCount(t *testing.T) {
	for _, tt := range []struct {
		name  string
		vulns vulnerabilities
		want  metrics
	}{
		{
			name: "a run that found nothing counts zero of each",
			want: metrics{Tool: "govulncheck-apply"},
		},
		{
			name:  "an advisory the last pass no longer reported is fixed",
			vulns: vulnerabilities{{osv: "GO-1", fixedIn: "v1.1.0"}},
			want: metrics{
				Tool: "govulncheck-apply", VulnerabilitiesFound: 1, VulnerabilitiesFixed: 1,
			},
		},
		{
			name:  "an advisory still reported with no published fix is unfixable",
			vulns: vulnerabilities{{osv: "GO-1", stillReported: true}},
			want: metrics{
				Tool: "govulncheck-apply", VulnerabilitiesFound: 1, VulnerabilitiesUnfixable: 1,
			},
		},
		{
			name:  "an advisory still reported despite a published fix is stuck",
			vulns: vulnerabilities{{osv: "GO-1", fixedIn: "v1.1.0", stillReported: true}},
			want: metrics{
				Tool: "govulncheck-apply", VulnerabilitiesFound: 1, VulnerabilitiesStuck: 1,
			},
		},
		{
			name: "every outcome at once",
			vulns: vulnerabilities{
				{osv: "GO-1", fixedIn: "v1.1.0"},
				{osv: "GO-2", fixedIn: "v2.1.0"},
				{osv: "GO-3", stillReported: true},
				{osv: "GO-4", fixedIn: "v4.1.0", stillReported: true},
			},
			want: metrics{
				Tool: "govulncheck-apply", VulnerabilitiesFound: 4, VulnerabilitiesFixed: 2,
				VulnerabilitiesUnfixable: 1, VulnerabilitiesStuck: 1,
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if diff := cmp.Diff(tt.want, tt.vulns.calculateMetrics()); diff != "" {
				t.Errorf("count() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
