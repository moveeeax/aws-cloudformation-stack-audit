// Package audit turns saved CloudFormation describe-* JSON into ranked findings.
package audit

import "time"

// Stack is the subset of a describe-stacks entry the checks need.
type Stack struct {
	StackID                     string            `json:"StackId"`
	StackName                   string            `json:"StackName"`
	Description                 string            `json:"Description"`
	CreationTime                *time.Time        `json:"CreationTime"`
	LastUpdatedTime             *time.Time        `json:"LastUpdatedTime"`
	StackStatus                 string            `json:"StackStatus"`
	StackStatusReason           string            `json:"StackStatusReason"`
	EnableTerminationProtection *bool             `json:"EnableTerminationProtection"`
	RoleARN                     string            `json:"RoleARN"`
	DriftInformation            *DriftInformation `json:"DriftInformation"`
	ParentID                    string            `json:"ParentId"`
	Tags                        []Tag             `json:"Tags"`
}

// DriftInformation mirrors the inline drift summary describe-stacks returns.
type DriftInformation struct {
	StackDriftStatus   string     `json:"StackDriftStatus"`
	LastCheckTimestamp *time.Time `json:"LastCheckTimestamp"`
}

// Tag is a stack-level tag.
type Tag struct {
	Key   string `json:"Key"`
	Value string `json:"Value"`
}

// Resource is the subset of a describe-stack-resources entry the checks need.
type Resource struct {
	StackName          string `json:"StackName"`
	StackID            string `json:"StackId"`
	LogicalResourceID  string `json:"LogicalResourceId"`
	PhysicalResourceID string `json:"PhysicalResourceId"`
	ResourceType       string `json:"ResourceType"`
	ResourceStatus     string `json:"ResourceStatus"`
}

// DriftStatus is a describe-stack-drift-detection-status response.
type DriftStatus struct {
	StackID                   string `json:"StackId"`
	StackDriftDetectionID     string `json:"StackDriftDetectionId"`
	StackDriftStatus          string `json:"StackDriftStatus"`
	DetectionStatus           string `json:"DetectionStatus"`
	DriftedStackResourceCount *int   `json:"DriftedStackResourceCount"`
}

// Inventory is everything loaded from disk, grouped per stack.
type Inventory struct {
	Stacks []Stack
	// Resources is keyed by stack name.
	Resources map[string][]Resource
	// Drift is keyed by stack name and, when known, by stack id too.
	Drift map[string]DriftStatus
	// Files lists the dumps that were parsed, in load order.
	Files []string
}

// Severity ranks a finding. Higher is worse.
type Severity int

// Severity levels, ordered.
const (
	Low Severity = iota + 1
	Medium
	High
)

// String renders the severity as the lowercase name used on the CLI.
func (s Severity) String() string {
	switch s {
	case High:
		return "high"
	case Medium:
		return "medium"
	case Low:
		return "low"
	}
	return "unknown"
}

// ParseSeverity accepts the lowercase severity names used by --fail-on.
func ParseSeverity(s string) (Severity, bool) {
	switch s {
	case "high":
		return High, true
	case "medium":
		return Medium, true
	case "low":
		return Low, true
	}
	return 0, false
}

// Finding is one problem with one stack.
type Finding struct {
	Severity Severity `json:"-"`
	Level    string   `json:"severity"`
	Check    string   `json:"check"`
	Stack    string   `json:"stack"`
	StackID  string   `json:"stack_id,omitempty"`
	Detail   string   `json:"detail"`
	Remedy   string   `json:"remedy,omitempty"`
}
