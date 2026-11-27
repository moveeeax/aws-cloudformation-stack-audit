// Command aws-cloudformation-stack-audit ranks CloudFormation stacks by risk
// using saved describe-* JSON dumps.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/moveeeax/aws-cloudformation-stack-audit/internal/audit"
)

// version is overridden at release time with -ldflags "-X main.version=v0.1.0".
var version = "dev"

const (
	exitOK       = 0
	exitFindings = 1
	exitUsage    = 2
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("aws-cloudformation-stack-audit", flag.ContinueOnError)
	fs.SetOutput(stderr)

	fromFiles := fs.String("from-files", "", "directory of JSON dumps, or a comma-separated list of files (required)")
	maxAgeDays := fs.Int("max-age-days", 365, "a healthy stack untouched for longer than this is reported as abandoned")
	only := fs.String("only", "", "comma-separated check ids to run (default: all)")
	ignoreStack := fs.String("ignore-stack", "", "regular expression; matching stack names are skipped entirely")
	failOn := fs.String("fail-on", "high", "lowest severity that makes the exit code 1: high, medium or low")
	asJSON := fs.Bool("json", false, "emit findings as JSON instead of a table")
	showVersion := fs.Bool("version", false, "print the version and exit")

	fs.Usage = func() {
		fmt.Fprintf(stderr, "aws-cloudformation-stack-audit %s\n\n", version)
		fmt.Fprintln(stderr, "Audits CloudFormation stacks from saved describe-stacks,")
		fmt.Fprintln(stderr, "describe-stack-resources and describe-stack-drift-detection-status dumps.")
		fmt.Fprintf(stderr, "\nUsage:\n  aws-cloudformation-stack-audit --from-files <dir|file,file> [flags]\n\nFlags:\n")
		fs.PrintDefaults()
		fmt.Fprintln(stderr, "\nChecks:")
		for _, c := range audit.Checks {
			fmt.Fprintf(stderr, "  %-26s %s\n", c.ID, c.Desc)
		}
		fmt.Fprintln(stderr, "\nExit codes:\n  0  no findings at or above --fail-on\n  1  findings at or above --fail-on\n  2  usage or input error")
	}

	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if *showVersion {
		fmt.Fprintln(stdout, version)
		return exitOK
	}
	if *fromFiles == "" {
		fmt.Fprintln(stderr, "error: --from-files is required")
		fs.Usage()
		return exitUsage
	}

	threshold, ok := audit.ParseSeverity(*failOn)
	if !ok {
		fmt.Fprintf(stderr, "error: --fail-on must be high, medium or low, got %q\n", *failOn)
		return exitUsage
	}

	opt := audit.Options{MaxAgeDays: *maxAgeDays, Now: time.Now().UTC()}

	if *only != "" {
		valid := map[string]bool{}
		for _, c := range audit.Checks {
			valid[c.ID] = true
		}
		opt.Only = map[string]bool{}
		for _, id := range strings.Split(*only, ",") {
			id = strings.TrimSpace(id)
			if id == "" {
				continue
			}
			if !valid[id] {
				fmt.Fprintf(stderr, "error: unknown check %q in --only\n", id)
				return exitUsage
			}
			opt.Only[id] = true
		}
	}

	if *ignoreStack != "" {
		re, err := regexp.Compile(*ignoreStack)
		if err != nil {
			fmt.Fprintf(stderr, "error: --ignore-stack is not a valid regexp: %v\n", err)
			return exitUsage
		}
		opt.IgnoreStack = re
	}

	inv, err := audit.Load(strings.Split(*fromFiles, ","))
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return exitUsage
	}

	findings := audit.Run(inv, opt)

	if *asJSON {
		err = audit.WriteJSON(stdout, findings)
	} else {
		err = audit.WriteTable(stdout, findings, len(inv.Stacks))
	}
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return exitUsage
	}

	if audit.Worst(findings) >= threshold {
		return exitFindings
	}
	return exitOK
}
