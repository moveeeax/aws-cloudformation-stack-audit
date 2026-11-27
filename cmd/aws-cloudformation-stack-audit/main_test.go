package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

const accountDir = "../../testdata/account"

func exec(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := run(args, &out, &errb)
	return code, out.String(), errb.String()
}

func TestFailOnHighExitsOneWhenHighFindingExists(t *testing.T) {
	code, out, _ := exec(t, "--from-files", accountDir, "--fail-on", "high")
	if code != exitFindings {
		t.Fatalf("exit = %d, want %d\n%s", code, exitFindings, out)
	}
	if !strings.Contains(out, "high") {
		t.Errorf("table should contain a high finding:\n%s", out)
	}
}

func TestFailOnHighExitsZeroWithoutHighFindings(t *testing.T) {
	// Only low-severity checks selected, so the high gate stays open.
	code, out, _ := exec(t, "--from-files", accountDir, "--only", "drift-not-checked,abandoned", "--fail-on", "high")
	if code != exitOK {
		t.Fatalf("exit = %d, want %d\n%s", code, exitOK, out)
	}
	code, _, _ = exec(t, "--from-files", accountDir, "--only", "drift-not-checked", "--fail-on", "low")
	if code != exitFindings {
		t.Fatalf("exit = %d with --fail-on low, want %d", code, exitFindings)
	}
}

func TestCleanAccountExitsZero(t *testing.T) {
	code, out, _ := exec(t, "--from-files", accountDir, "--ignore-stack", ".")
	if code != exitOK {
		t.Fatalf("exit = %d, want %d\n%s", code, exitOK, out)
	}
	if !strings.Contains(out, "no findings") {
		t.Errorf("unexpected output:\n%s", out)
	}
}

func TestJSONOutput(t *testing.T) {
	code, out, _ := exec(t, "--from-files", accountDir, "--json")
	if code != exitFindings {
		t.Fatalf("exit = %d, want %d", code, exitFindings)
	}
	var findings []struct {
		Severity string `json:"severity"`
		Check    string `json:"check"`
		Stack    string `json:"stack"`
		Detail   string `json:"detail"`
	}
	if err := json.Unmarshal([]byte(out), &findings); err != nil {
		t.Fatalf("--json did not emit valid JSON: %v\n%s", err, out)
	}
	if len(findings) == 0 {
		t.Fatal("no findings decoded")
	}
	for _, f := range findings {
		if f.Severity == "" || f.Check == "" || f.Stack == "" || f.Detail == "" {
			t.Fatalf("incomplete finding: %+v", f)
		}
	}
}

func TestCommaSeparatedFileList(t *testing.T) {
	code, out, _ := exec(t,
		"--from-files", accountDir+"/stacks.json,"+accountDir+"/prod-db-resources.json",
		"--only", "no-termination-protection")
	if code != exitFindings {
		t.Fatalf("exit = %d, want %d\n%s", code, exitFindings, out)
	}
	if !strings.Contains(out, "prod-db") {
		t.Errorf("expected prod-db in output:\n%s", out)
	}
}

func TestUsageErrors(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"no from-files", []string{}, "--from-files is required"},
		{"bad fail-on", []string{"--from-files", accountDir, "--fail-on", "critical"}, "--fail-on must be"},
		{"unknown check", []string{"--from-files", accountDir, "--only", "nope"}, "unknown check"},
		{"bad regexp", []string{"--from-files", accountDir, "--ignore-stack", "("}, "not a valid regexp"},
		{"missing dump", []string{"--from-files", "../../testdata/nowhere"}, "no such file"},
		{"unknown flag", []string{"--from-files", accountDir, "--wat"}, "flag provided but not defined"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			code, _, errOut := exec(t, c.args...)
			if code != exitUsage {
				t.Fatalf("exit = %d, want %d", code, exitUsage)
			}
			if !strings.Contains(errOut, c.want) {
				t.Fatalf("stderr %q does not mention %q", errOut, c.want)
			}
		})
	}
}

func TestVersion(t *testing.T) {
	code, out, _ := exec(t, "--version")
	if code != exitOK {
		t.Fatalf("exit = %d, want 0", code)
	}
	if strings.TrimSpace(out) != version {
		t.Errorf("printed %q, want %q", out, version)
	}
}

func TestHelpDocumentsEveryFlagAndCheck(t *testing.T) {
	_, _, errOut := exec(t, "--help")
	for _, want := range []string{
		"--from-files", "-max-age-days", "-only", "-ignore-stack", "-fail-on", "-json", "-version",
		"broken-state", "never-deployed", "no-termination-protection", "drifted",
		"drift-not-checked", "abandoned", "no-stack-role", "iam-wildcard",
		"Exit codes",
	} {
		if !strings.Contains(errOut, strings.TrimPrefix(want, "-")) {
			t.Errorf("--help does not document %q", want)
		}
	}
}
