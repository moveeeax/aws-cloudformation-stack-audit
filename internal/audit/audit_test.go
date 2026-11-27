package audit

import (
	"bytes"
	"encoding/json"
	"regexp"
	"strings"
	"testing"
	"time"
)

// fixedNow keeps the abandoned check deterministic: lambda-api in the fixtures
// was last updated exactly 500 days before this instant.
var fixedNow = time.Date(2026, 11, 27, 0, 0, 0, 0, time.UTC)

func loadAccount(t *testing.T) *Inventory {
	t.Helper()
	inv, err := Load([]string{accountDir})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return inv
}

func findingsFor(fs []Finding, stack string) map[string]Finding {
	out := map[string]Finding{}
	for _, f := range fs {
		if f.Stack == stack {
			out[f.Check] = f
		}
	}
	return out
}

func TestBrokenStateIsHigh(t *testing.T) {
	fs := Run(loadAccount(t), Options{Now: fixedNow})
	f, ok := findingsFor(fs, "legacy-rollback")[CheckBrokenState]
	if !ok {
		t.Fatalf("legacy-rollback missing %s; got %v", CheckBrokenState, findingsFor(fs, "legacy-rollback"))
	}
	if f.Severity != High {
		t.Errorf("severity = %s, want high", f.Severity)
	}
	if !strings.Contains(f.Detail, "UPDATE_ROLLBACK_FAILED") {
		t.Errorf("detail %q does not name the state", f.Detail)
	}
	if strings.Contains(f.Detail, "\n") {
		t.Errorf("detail must stay on one line, got %q", f.Detail)
	}
	if !strings.Contains(f.Remedy, "continue-update-rollback") {
		t.Errorf("remedy %q should suggest continue-update-rollback", f.Remedy)
	}
}

func TestTerminationProtectionOnlyForStatefulStacks(t *testing.T) {
	fs := Run(loadAccount(t), Options{Now: fixedNow})

	f, ok := findingsFor(fs, "prod-db")[CheckNoTermProtect]
	if !ok {
		t.Fatal("prod-db owns an RDS instance with protection off and was not reported")
	}
	if f.Severity != High {
		t.Errorf("severity = %s, want high", f.Severity)
	}
	if !strings.Contains(f.Detail, "AWS::RDS::DBInstance") {
		t.Errorf("detail %q should name the stateful resource", f.Detail)
	}

	if _, ok := findingsFor(fs, "lambda-api")[CheckNoTermProtect]; ok {
		t.Error("lambda-api holds only stateless resources and must not be reported")
	}
}

func TestTerminationProtectionNeedsResourceDump(t *testing.T) {
	// Same stack, no resource dump loaded: nothing is known about what it owns,
	// so the check stays quiet instead of guessing.
	inv := &Inventory{
		Stacks:    []Stack{{StackName: "prod-db", StackStatus: "UPDATE_COMPLETE", EnableTerminationProtection: boolp(false), RoleARN: "arn:x"}},
		Resources: map[string][]Resource{},
		Drift:     map[string]DriftStatus{},
	}
	fs := Run(inv, Options{Now: fixedNow, Only: map[string]bool{CheckNoTermProtect: true}})
	if len(fs) != 0 {
		t.Fatalf("expected no findings without a resource dump, got %v", fs)
	}
}

func TestDriftDumpOverridesInlineSummary(t *testing.T) {
	// prod-db reports NOT_CHECKED inline but a drift dump says DRIFTED.
	fs := Run(loadAccount(t), Options{Now: fixedNow})
	got := findingsFor(fs, "prod-db")
	f, ok := got[CheckDrifted]
	if !ok {
		t.Fatalf("prod-db missing %s; got %v", CheckDrifted, got)
	}
	if f.Severity != Medium {
		t.Errorf("drifted severity = %s, want medium", f.Severity)
	}
	if !strings.Contains(f.Detail, "3 drifted resources") {
		t.Errorf("detail %q should carry the drifted resource count", f.Detail)
	}
	if _, ok := got[CheckDriftNotChecke]; ok {
		t.Error("prod-db must not be reported as both drifted and never-checked")
	}
}

func TestDriftNotCheckedIsLowerSeverity(t *testing.T) {
	fs := Run(loadAccount(t), Options{Now: fixedNow})
	f, ok := findingsFor(fs, "legacy-rollback")[CheckDriftNotChecke]
	if !ok {
		t.Fatal("legacy-rollback reports NOT_CHECKED and was not flagged")
	}
	if f.Severity != Low {
		t.Errorf("drift-not-checked severity = %s, want low", f.Severity)
	}
	if f.Severity >= Medium {
		t.Error("drift-not-checked must rank below drifted")
	}
	if _, ok := findingsFor(fs, "lambda-api")[CheckDriftNotChecke]; ok {
		t.Error("lambda-api is IN_SYNC and must not be flagged")
	}
}

func TestAbandonedRespectsMaxAgeDays(t *testing.T) {
	inv := loadAccount(t)

	f, ok := findingsFor(Run(inv, Options{Now: fixedNow, MaxAgeDays: 365}), "lambda-api")[CheckAbandoned]
	if !ok {
		t.Fatal("lambda-api was last updated 500 days ago and was not flagged at --max-age-days 365")
	}
	if !strings.Contains(f.Detail, "500 days ago") {
		t.Errorf("detail %q should state the age", f.Detail)
	}

	if _, ok := findingsFor(Run(inv, Options{Now: fixedNow, MaxAgeDays: 900}), "lambda-api")[CheckAbandoned]; ok {
		t.Error("lambda-api must not be flagged at --max-age-days 900")
	}
}

func TestAbandonedSkipsUnhealthyStacks(t *testing.T) {
	// legacy-rollback has not been touched since 2024 but it is already
	// reported as broken-state; calling it abandoned too is just noise.
	fs := Run(loadAccount(t), Options{Now: fixedNow, MaxAgeDays: 365})
	if _, ok := findingsFor(fs, "legacy-rollback")[CheckAbandoned]; ok {
		t.Error("a failed stack must not also be reported as abandoned")
	}
}

func TestNeverDeployedAndNoStackRole(t *testing.T) {
	fs := Run(loadAccount(t), Options{Now: fixedNow})
	got := findingsFor(fs, "changeset-only")
	if f, ok := got[CheckNeverDeployed]; !ok {
		t.Error("changeset-only is REVIEW_IN_PROGRESS and was not flagged")
	} else if f.Severity != Medium {
		t.Errorf("never-deployed severity = %s, want medium", f.Severity)
	}
	if _, ok := got[CheckNoStackRole]; !ok {
		t.Error("changeset-only has no RoleARN and was not flagged")
	}
	if _, ok := findingsFor(fs, "prod-db")[CheckNoStackRole]; ok {
		t.Error("prod-db has a service role and must not be flagged")
	}
}

func TestIAMWildcard(t *testing.T) {
	fs := Run(loadAccount(t), Options{Now: fixedNow})
	var hits []Finding
	for _, f := range fs {
		if f.Check == CheckIAMWildcard {
			hits = append(hits, f)
		}
	}
	if len(hits) != 1 {
		t.Fatalf("want exactly one iam-wildcard finding, got %d: %v", len(hits), hits)
	}
	if hits[0].Stack != "iam-bootstrap" || !strings.Contains(hits[0].Detail, "BreakGlassPolicy") {
		t.Errorf("unexpected finding %+v", hits[0])
	}
	if hits[0].Severity != High {
		t.Errorf("severity = %s, want high", hits[0].Severity)
	}
}

func TestDeletedStacksAreSkipped(t *testing.T) {
	fs := Run(loadAccount(t), Options{Now: fixedNow, MaxAgeDays: 1})
	if got := findingsFor(fs, "old-deleted"); len(got) != 0 {
		t.Errorf("DELETE_COMPLETE stack produced findings: %v", got)
	}
}

func TestOnlyFilter(t *testing.T) {
	fs := Run(loadAccount(t), Options{Now: fixedNow, Only: map[string]bool{
		CheckBrokenState: true, CheckNoTermProtect: true,
	}})
	if len(fs) == 0 {
		t.Fatal("no findings returned")
	}
	for _, f := range fs {
		if f.Check != CheckBrokenState && f.Check != CheckNoTermProtect {
			t.Fatalf("--only leaked check %q", f.Check)
		}
	}
}

func TestIgnoreStackSkipsEverything(t *testing.T) {
	fs := Run(loadAccount(t), Options{Now: fixedNow, IgnoreStack: regexp.MustCompile(`^(legacy|changeset|iam)-`)})
	for _, f := range fs {
		if strings.HasPrefix(f.Stack, "legacy-") || strings.HasPrefix(f.Stack, "changeset-") || strings.HasPrefix(f.Stack, "iam-") {
			t.Fatalf("--ignore-stack did not skip %q", f.Stack)
		}
	}
	if len(fs) == 0 {
		t.Fatal("ignoring three stacks should not silence the rest")
	}
}

func TestFindingsSortedBySeverity(t *testing.T) {
	fs := Run(loadAccount(t), Options{Now: fixedNow, MaxAgeDays: 365})
	for i := 1; i < len(fs); i++ {
		if fs[i-1].Severity < fs[i].Severity {
			t.Fatalf("findings not sorted: %s before %s", fs[i-1].Severity, fs[i].Severity)
		}
	}
	if Worst(fs) != High {
		t.Errorf("Worst = %s, want high", Worst(fs))
	}
	if Worst(nil) != 0 {
		t.Error("Worst of no findings must be zero")
	}
}

func TestLevelMirrorsSeverity(t *testing.T) {
	for _, f := range Run(loadAccount(t), Options{Now: fixedNow}) {
		if f.Level != f.Severity.String() {
			t.Fatalf("finding %s/%s has level %q", f.Stack, f.Check, f.Level)
		}
	}
}

func TestParseSeverity(t *testing.T) {
	for in, want := range map[string]Severity{"high": High, "medium": Medium, "low": Low} {
		got, ok := ParseSeverity(in)
		if !ok || got != want {
			t.Errorf("ParseSeverity(%q) = %v, %v", in, got, ok)
		}
	}
	if _, ok := ParseSeverity("critical"); ok {
		t.Error("ParseSeverity accepted an unknown level")
	}
	if Severity(99).String() != "unknown" {
		t.Error("unexpected severity should render as unknown")
	}
}

func TestEveryCheckIDIsReachable(t *testing.T) {
	fs := Run(loadAccount(t), Options{Now: fixedNow, MaxAgeDays: 365})
	seen := map[string]bool{}
	for _, f := range fs {
		seen[f.Check] = true
	}
	for _, c := range Checks {
		if !seen[c.ID] {
			t.Errorf("check %q is documented but no fixture triggers it", c.ID)
		}
	}
}

func TestWriteJSONIsValid(t *testing.T) {
	var buf bytes.Buffer
	fs := Run(loadAccount(t), Options{Now: fixedNow, MaxAgeDays: 365})
	if err := WriteJSON(&buf, fs); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}
	var decoded []map[string]any
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if len(decoded) != len(fs) {
		t.Fatalf("encoded %d objects, want %d", len(decoded), len(fs))
	}
	for _, o := range decoded {
		for _, k := range []string{"severity", "check", "stack", "detail"} {
			if _, ok := o[k]; !ok {
				t.Fatalf("finding %v missing key %q", o, k)
			}
		}
	}

	buf.Reset()
	if err := WriteJSON(&buf, nil); err != nil {
		t.Fatalf("WriteJSON(nil): %v", err)
	}
	if strings.TrimSpace(buf.String()) != "[]" {
		t.Errorf("no findings should encode as [], got %q", buf.String())
	}
}

func TestWriteTable(t *testing.T) {
	var buf bytes.Buffer
	fs := Run(loadAccount(t), Options{Now: fixedNow, MaxAgeDays: 365})
	if err := WriteTable(&buf, fs, 6); err != nil {
		t.Fatalf("WriteTable: %v", err)
	}
	out := buf.String()
	for _, want := range []string{"SEVERITY", "CHECK", "STACK", "DETAIL", "prod-db", "across 6 stack(s)"} {
		if !strings.Contains(out, want) {
			t.Errorf("table output missing %q:\n%s", want, out)
		}
	}

	buf.Reset()
	if err := WriteTable(&buf, nil, 3); err != nil {
		t.Fatalf("WriteTable(nil): %v", err)
	}
	if !strings.Contains(buf.String(), "no findings across 3 stack(s)") {
		t.Errorf("unexpected clean output %q", buf.String())
	}
}

func boolp(b bool) *bool { return &b }
