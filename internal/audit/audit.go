package audit

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Check ids, in the order they appear in --help and in the report.
const (
	CheckBrokenState    = "broken-state"
	CheckNeverDeployed  = "never-deployed"
	CheckNoTermProtect  = "no-termination-protection"
	CheckDrifted        = "drifted"
	CheckDriftNotChecke = "drift-not-checked"
	CheckAbandoned      = "abandoned"
	CheckNoStackRole    = "no-stack-role"
	CheckIAMWildcard    = "iam-wildcard"
)

// Checks lists every check id with a one-line description, for --help.
var Checks = []struct {
	ID, Desc string
}{
	{CheckBrokenState, "stack is stuck in a *_FAILED state and needs manual recovery"},
	{CheckNeverDeployed, "stack sits in REVIEW_IN_PROGRESS and was never deployed"},
	{CheckNoTermProtect, "termination protection is off on a stack owning stateful resources"},
	{CheckDrifted, "drift detection reported DRIFTED"},
	{CheckDriftNotChecke, "drift was never checked for this stack"},
	{CheckAbandoned, "healthy stack untouched for longer than --max-age-days"},
	{CheckNoStackRole, "stack has no service role, so it deploys with the caller's permissions"},
	{CheckIAMWildcard, "stack owns an IAM resource whose name looks admin- or wildcard-shaped"},
}

// Options drives a run.
type Options struct {
	MaxAgeDays  int
	Only        map[string]bool
	IgnoreStack *regexp.Regexp
	// Now is injected so the abandoned check is deterministic in tests.
	Now time.Time
}

var brokenStates = map[string]bool{
	"CREATE_FAILED":          true,
	"ROLLBACK_FAILED":        true,
	"UPDATE_ROLLBACK_FAILED": true,
	"UPDATE_FAILED":          true,
	"DELETE_FAILED":          true,
	"IMPORT_ROLLBACK_FAILED": true,
}

var healthyStates = map[string]bool{
	"CREATE_COMPLETE":          true,
	"UPDATE_COMPLETE":          true,
	"UPDATE_ROLLBACK_COMPLETE": true,
	"IMPORT_COMPLETE":          true,
}

// statefulTypes are resource types whose deletion loses data or breaks the
// network for everything on top of it.
var statefulTypes = map[string]bool{
	"AWS::RDS::DBInstance":               true,
	"AWS::RDS::DBCluster":                true,
	"AWS::S3::Bucket":                    true,
	"AWS::DynamoDB::Table":               true,
	"AWS::DynamoDB::GlobalTable":         true,
	"AWS::EFS::FileSystem":               true,
	"AWS::EC2::VPC":                      true,
	"AWS::EC2::Volume":                   true,
	"AWS::FSx::FileSystem":               true,
	"AWS::Redshift::Cluster":             true,
	"AWS::DocDB::DBCluster":              true,
	"AWS::ElastiCache::CacheCluster":     true,
	"AWS::ElastiCache::ReplicationGroup": true,
	"AWS::OpenSearchService::Domain":     true,
	"AWS::Elasticsearch::Domain":         true,
}

var iamTypes = map[string]bool{
	"AWS::IAM::Role":          true,
	"AWS::IAM::Policy":        true,
	"AWS::IAM::ManagedPolicy": true,
	"AWS::IAM::User":          true,
	"AWS::IAM::Group":         true,
}

// wildcardNames matches identifiers that give away a blanket grant. Resource
// dumps carry no policy document, so the name is all there is to go on.
var wildcardNames = regexp.MustCompile(`(?i)(administratoraccess|poweruseraccess|fullaccess|allowall|\badmin\b|\*)`)

// Run applies every selected check to the inventory and returns the findings
// sorted by severity, then stack name, then check id.
func Run(inv *Inventory, opt Options) []Finding {
	if opt.MaxAgeDays <= 0 {
		opt.MaxAgeDays = 365
	}
	if opt.Now.IsZero() {
		opt.Now = time.Now().UTC()
	}

	var out []Finding
	add := func(f Finding) {
		if len(opt.Only) > 0 && !opt.Only[f.Check] {
			return
		}
		f.Level = f.Severity.String()
		out = append(out, f)
	}

	for _, s := range inv.Stacks {
		if s.StackStatus == "DELETE_COMPLETE" {
			continue
		}
		if opt.IgnoreStack != nil && opt.IgnoreStack.MatchString(s.StackName) {
			continue
		}

		if brokenStates[s.StackStatus] {
			detail := s.StackStatus
			if s.StackStatusReason != "" {
				detail += ": " + firstLine(s.StackStatusReason)
			}
			add(Finding{
				Severity: High, Check: CheckBrokenState, Stack: s.StackName, StackID: s.StackID,
				Detail: detail,
				Remedy: fmt.Sprintf("aws cloudformation continue-update-rollback --stack-name %s", s.StackName),
			})
		}

		if s.StackStatus == "REVIEW_IN_PROGRESS" {
			add(Finding{
				Severity: Medium, Check: CheckNeverDeployed, Stack: s.StackName, StackID: s.StackID,
				Detail: "REVIEW_IN_PROGRESS: a change set was created but never executed",
				Remedy: fmt.Sprintf("aws cloudformation delete-stack --stack-name %s", s.StackName),
			})
		}

		if s.EnableTerminationProtection != nil && !*s.EnableTerminationProtection {
			if kinds := statefulKinds(inv.ResourcesFor(s)); len(kinds) > 0 {
				add(Finding{
					Severity: High, Check: CheckNoTermProtect, Stack: s.StackName, StackID: s.StackID,
					Detail: "termination protection off; owns " + strings.Join(kinds, ", "),
					Remedy: fmt.Sprintf("aws cloudformation update-termination-protection --enable-termination-protection --stack-name %s", s.StackName),
				})
			}
		}

		switch driftStatus(inv, s) {
		case "DRIFTED":
			detail := "drift detection reported DRIFTED"
			if d, ok := inv.DriftFor(s); ok && d.DriftedStackResourceCount != nil {
				detail = fmt.Sprintf("drift detection reported DRIFTED (%d drifted resources)", *d.DriftedStackResourceCount)
			}
			add(Finding{
				Severity: Medium, Check: CheckDrifted, Stack: s.StackName, StackID: s.StackID,
				Detail: detail,
				Remedy: fmt.Sprintf("aws cloudformation describe-stack-resource-drifts --stack-name %s", s.StackName),
			})
		case "NOT_CHECKED", "UNKNOWN", "":
			add(Finding{
				Severity: Low, Check: CheckDriftNotChecke, Stack: s.StackName, StackID: s.StackID,
				Detail: "drift was never checked, so the stack's real state is unknown",
				Remedy: fmt.Sprintf("aws cloudformation detect-stack-drift --stack-name %s", s.StackName),
			})
		}

		if healthyStates[s.StackStatus] {
			if when, ok := lastTouched(s); ok {
				age := int(opt.Now.Sub(when).Hours() / 24)
				if age > opt.MaxAgeDays {
					add(Finding{
						Severity: Low, Check: CheckAbandoned, Stack: s.StackName, StackID: s.StackID,
						Detail: fmt.Sprintf("last changed %d days ago (%s)", age, when.UTC().Format("2006-01-02")),
					})
				}
			}
		}

		if s.RoleARN == "" {
			add(Finding{
				Severity: Medium, Check: CheckNoStackRole, Stack: s.StackName, StackID: s.StackID,
				Detail: "no service role: updates run with whatever permissions the caller has",
			})
		}

		for _, r := range inv.ResourcesFor(s) {
			if !iamTypes[r.ResourceType] {
				continue
			}
			name := r.PhysicalResourceID
			if name == "" {
				name = r.LogicalResourceID
			}
			if !wildcardNames.MatchString(name) && !wildcardNames.MatchString(r.LogicalResourceID) {
				continue
			}
			add(Finding{
				Severity: High, Check: CheckIAMWildcard, Stack: s.StackName, StackID: s.StackID,
				Detail: fmt.Sprintf("%s %s looks like a blanket grant (%s)", r.ResourceType, r.LogicalResourceID, name),
			})
		}
	}

	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Severity != out[j].Severity {
			return out[i].Severity > out[j].Severity
		}
		if out[i].Stack != out[j].Stack {
			return out[i].Stack < out[j].Stack
		}
		return out[i].Check < out[j].Check
	})
	return out
}

// Worst returns the highest severity among the findings, or 0 for none.
func Worst(fs []Finding) Severity {
	var worst Severity
	for _, f := range fs {
		if f.Severity > worst {
			worst = f.Severity
		}
	}
	return worst
}

func driftStatus(inv *Inventory, s Stack) string {
	if d, ok := inv.DriftFor(s); ok && d.StackDriftStatus != "" {
		return d.StackDriftStatus
	}
	if s.DriftInformation != nil {
		return s.DriftInformation.StackDriftStatus
	}
	return ""
}

func statefulKinds(rs []Resource) []string {
	seen := map[string]bool{}
	var out []string
	for _, r := range rs {
		if statefulTypes[r.ResourceType] && !seen[r.ResourceType] {
			seen[r.ResourceType] = true
			out = append(out, r.ResourceType)
		}
	}
	sort.Strings(out)
	return out
}

func lastTouched(s Stack) (time.Time, bool) {
	if s.LastUpdatedTime != nil {
		return *s.LastUpdatedTime, true
	}
	if s.CreationTime != nil {
		return *s.CreationTime, true
	}
	return time.Time{}, false
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}
