package audit

import (
	"path/filepath"
	"strings"
	"testing"
)

const accountDir = "../../testdata/account"

func TestLoadDirectory(t *testing.T) {
	inv, err := Load([]string{accountDir})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got, want := len(inv.Stacks), 6; got != want {
		t.Fatalf("loaded %d stacks, want %d", got, want)
	}
	if inv.Stacks[0].StackName != "changeset-only" {
		t.Errorf("stacks not sorted by name, first is %q", inv.Stacks[0].StackName)
	}
	if got := len(inv.Resources["prod-db"]); got != 3 {
		t.Errorf("prod-db has %d resources, want 3", got)
	}
	if len(inv.Files) != 5 {
		t.Errorf("parsed %d files, want 5: %v", len(inv.Files), inv.Files)
	}
}

func TestLoadCommaListAndDriftKeying(t *testing.T) {
	inv, err := Load([]string{
		filepath.Join(accountDir, "stacks.json"),
		filepath.Join(accountDir, "prod-db-drift.json"),
	})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(inv.Stacks) != 6 {
		t.Fatalf("loaded %d stacks, want 6", len(inv.Stacks))
	}
	if len(inv.Resources) != 0 {
		t.Errorf("expected no resource dumps, got %v", inv.Resources)
	}
	var prodDB Stack
	for _, s := range inv.Stacks {
		if s.StackName == "prod-db" {
			prodDB = s
		}
	}
	d, ok := inv.DriftFor(prodDB)
	if !ok {
		t.Fatal("drift dump not matched to prod-db")
	}
	if d.StackDriftStatus != "DRIFTED" {
		t.Errorf("drift status = %q, want DRIFTED", d.StackDriftStatus)
	}
}

func TestLoadDeduplicatesStacks(t *testing.T) {
	p := filepath.Join(accountDir, "stacks.json")
	inv, err := Load([]string{p, p})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(inv.Stacks) != 6 {
		t.Fatalf("loaded %d stacks from a duplicated dump, want 6", len(inv.Stacks))
	}
}

func TestLoadErrors(t *testing.T) {
	cases := []struct {
		name, path, want string
	}{
		{"unknown shape", "../../testdata/bad/unknown-shape.json", "unrecognised dump"},
		{"not json", "../../testdata/bad/broken.json", "not a JSON object"},
		{"missing", "../../testdata/does-not-exist.json", "no such file"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := Load([]string{c.path}); err == nil {
				t.Fatal("expected an error")
			} else if !strings.Contains(err.Error(), c.want) {
				t.Fatalf("error %q does not mention %q", err, c.want)
			}
		})
	}
}

func TestLoadEmptyDirectory(t *testing.T) {
	dir := t.TempDir()
	if _, err := Load([]string{dir}); err == nil {
		t.Fatal("expected an error for a directory with no dumps")
	}
}

func TestStackNameFromID(t *testing.T) {
	cases := map[string]string{
		"arn:aws:cloudformation:eu-west-1:1:stack/prod-vpc/abc-123": "prod-vpc",
		"arn:aws:cloudformation:eu-west-1:1:stack/prod-vpc":         "prod-vpc",
		"prod-vpc": "",
	}
	for in, want := range cases {
		if got := stackNameFromID(in); got != want {
			t.Errorf("stackNameFromID(%q) = %q, want %q", in, got, want)
		}
	}
}
