package audit

import (
	"encoding/json"
	"fmt"
	"io"
	"text/tabwriter"
)

// WriteTable prints the findings as an aligned table with a one-line summary.
func WriteTable(w io.Writer, fs []Finding, stacks int) error {
	if len(fs) == 0 {
		_, err := fmt.Fprintf(w, "no findings across %d stack(s)\n", stacks)
		return err
	}
	tw := tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "SEVERITY\tCHECK\tSTACK\tDETAIL")
	for _, f := range fs {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", f.Severity, f.Check, f.Stack, f.Detail)
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	high, medium, low := count(fs)
	_, err := fmt.Fprintf(w, "\n%d finding(s) across %d stack(s): %d high, %d medium, %d low\n",
		len(fs), stacks, high, medium, low)
	return err
}

// WriteJSON prints one JSON object per finding inside a single array, so the
// output stays valid JSON for jq even when there are no findings.
func WriteJSON(w io.Writer, fs []Finding) error {
	if fs == nil {
		fs = []Finding{}
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(fs)
}

func count(fs []Finding) (high, medium, low int) {
	for _, f := range fs {
		switch f.Severity {
		case High:
			high++
		case Medium:
			medium++
		case Low:
			low++
		}
	}
	return
}
