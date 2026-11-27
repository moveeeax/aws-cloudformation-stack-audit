package audit

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Load reads describe-stacks, describe-stack-resources and
// describe-stack-drift-detection-status dumps. Each spec is either a directory
// (every *.json inside it, non-recursive) or a single file. The shape of each
// file decides how it is used, so the caller does not have to label the dumps.
func Load(specs []string) (*Inventory, error) {
	files, err := expand(specs)
	if err != nil {
		return nil, err
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("no JSON dumps found in %s", strings.Join(specs, ", "))
	}

	inv := &Inventory{
		Resources: map[string][]Resource{},
		Drift:     map[string]DriftStatus{},
	}
	seen := map[string]bool{}

	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		var probe map[string]json.RawMessage
		if err := json.Unmarshal(raw, &probe); err != nil {
			return nil, fmt.Errorf("%s: not a JSON object: %w", filepath.Base(f), err)
		}

		switch {
		case probe["Stacks"] != nil:
			var doc struct{ Stacks []Stack }
			if err := json.Unmarshal(raw, &doc); err != nil {
				return nil, fmt.Errorf("%s: %w", filepath.Base(f), err)
			}
			for _, s := range doc.Stacks {
				key := s.StackID
				if key == "" {
					key = s.StackName
				}
				if seen[key] {
					continue
				}
				seen[key] = true
				inv.Stacks = append(inv.Stacks, s)
			}
		case probe["StackResources"] != nil:
			var doc struct{ StackResources []Resource }
			if err := json.Unmarshal(raw, &doc); err != nil {
				return nil, fmt.Errorf("%s: %w", filepath.Base(f), err)
			}
			for _, r := range doc.StackResources {
				inv.Resources[r.StackName] = append(inv.Resources[r.StackName], r)
			}
		case probe["StackDriftDetectionId"] != nil:
			var doc DriftStatus
			if err := json.Unmarshal(raw, &doc); err != nil {
				return nil, fmt.Errorf("%s: %w", filepath.Base(f), err)
			}
			if doc.StackID != "" {
				inv.Drift[doc.StackID] = doc
				if name := stackNameFromID(doc.StackID); name != "" {
					inv.Drift[name] = doc
				}
			}
		default:
			return nil, fmt.Errorf("%s: unrecognised dump; expected Stacks, StackResources or StackDriftDetectionId at the top level", filepath.Base(f))
		}
		inv.Files = append(inv.Files, f)
	}

	sort.Slice(inv.Stacks, func(i, j int) bool { return inv.Stacks[i].StackName < inv.Stacks[j].StackName })
	return inv, nil
}

func expand(specs []string) ([]string, error) {
	var out []string
	for _, spec := range specs {
		spec = strings.TrimSpace(spec)
		if spec == "" {
			continue
		}
		st, err := os.Stat(spec)
		if err != nil {
			return nil, err
		}
		if !st.IsDir() {
			out = append(out, spec)
			continue
		}
		entries, err := os.ReadDir(spec)
		if err != nil {
			return nil, err
		}
		var inDir []string
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
				continue
			}
			inDir = append(inDir, filepath.Join(spec, e.Name()))
		}
		sort.Strings(inDir)
		out = append(out, inDir...)
	}
	return out, nil
}

// stackNameFromID pulls the stack name out of a stack ARN:
// arn:aws:cloudformation:eu-west-1:1234:stack/prod-vpc/abc-123 -> prod-vpc
func stackNameFromID(id string) string {
	i := strings.Index(id, ":stack/")
	if i < 0 {
		return ""
	}
	rest := id[i+len(":stack/"):]
	if j := strings.Index(rest, "/"); j >= 0 {
		return rest[:j]
	}
	return rest
}

// ResourcesFor returns the loaded resources for a stack, matching on name and
// then on the name embedded in the stack id.
func (inv *Inventory) ResourcesFor(s Stack) []Resource {
	if rs, ok := inv.Resources[s.StackName]; ok {
		return rs
	}
	if name := stackNameFromID(s.StackID); name != "" {
		return inv.Resources[name]
	}
	return nil
}

// DriftFor returns an explicit drift-detection result for a stack, if one was
// loaded. It takes precedence over the inline DriftInformation summary.
func (inv *Inventory) DriftFor(s Stack) (DriftStatus, bool) {
	if d, ok := inv.Drift[s.StackID]; ok && s.StackID != "" {
		return d, true
	}
	d, ok := inv.Drift[s.StackName]
	return d, ok
}
