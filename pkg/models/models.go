package models

import (
	"crypto/sha256"
	"fmt"
	"strings"
)

// Severity represents the severity level of a finding.
type Severity int

const (
	SeverityInfo     Severity = 0
	SeverityWarning  Severity = 1
	SeverityHigh     Severity = 2
	SeverityCritical Severity = 3
)

// String returns the human-readable severity label.
func (s Severity) String() string {
	switch s {
	case SeverityInfo:
		return "INFO"
	case SeverityWarning:
		return "WARNING"
	case SeverityHigh:
		return "HIGH"
	case SeverityCritical:
		return "CRITICAL"
	default:
		return fmt.Sprintf("UNKNOWN(%d)", int(s))
	}
}

// ParseSeverity parses a case-insensitive severity string.
func ParseSeverity(s string) (Severity, error) {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "INFO":
		return SeverityInfo, nil
	case "WARNING":
		return SeverityWarning, nil
	case "HIGH":
		return SeverityHigh, nil
	case "CRITICAL":
		return SeverityCritical, nil
	default:
		return SeverityInfo, fmt.Errorf("unknown severity: %q", s)
	}
}

// Finding represents a single security finding from the analyzer.
type Finding struct {
	RuleID            string
	Severity          Severity
	Title             string
	File              string
	Description       string
	Remediation       string
	ResourceKind      string
	ResourceName      string
	ResourceNamespace string // empty for cluster-scoped resources
	Suppressed        bool
	Fingerprint       string // SHA256 of "rule_id|resource_kind|resource_name|namespace|file"
}

// ComputeFingerprint fills the Fingerprint field with a SHA256 hash
// derived from the finding's identifying fields, including the file path.
func (f *Finding) ComputeFingerprint() {
	data := fmt.Sprintf("%s|%s|%s|%s|%s", f.RuleID, f.ResourceKind, f.ResourceName, f.ResourceNamespace, f.File)
	hash := sha256.Sum256([]byte(data))
	f.Fingerprint = fmt.Sprintf("%x", hash)
}

// BindingScope describes how a role is bound: cluster-wide, namespace-scoped,
// or unbound. It also tracks which bindings reference the role and the types
// of subjects involved.
type BindingScope struct {
	ClusterWide     bool
	NamespaceScoped bool
	Unbound         bool
	ClusterBindings []string
	RoleBindings    []string
	SubjectTypes    map[string]int // "ServiceAccount", "Group", "User" -> count
}

// ClusterRoleData holds a parsed ClusterRole resource.
type ClusterRoleData struct {
	Rules []map[string]interface{}
	File  string
	Doc   map[string]interface{}
}

// RoleData holds a parsed Role resource.
type RoleData struct {
	Rules     []map[string]interface{}
	Namespace string
	File      string
	Doc       map[string]interface{}
}

// BindingData holds a parsed ClusterRoleBinding or RoleBinding resource.
type BindingData struct {
	Name      string
	Namespace string // empty for ClusterRoleBinding
	RoleRef   map[string]interface{}
	Subjects  []map[string]interface{}
	File      string
	Doc       map[string]interface{}
}

// SAData holds a parsed ServiceAccount resource.
type SAData struct {
	Name      string
	Namespace string
	File      string
	Doc       map[string]interface{}
}

// PodData holds a parsed Pod resource.
type PodData struct {
	Name               string
	Namespace          string
	ServiceAccountName string
	File               string
	Doc                map[string]interface{}
}

// WorkloadData holds a parsed workload controller (Deployment, DaemonSet, etc.).
type WorkloadData struct {
	Name               string
	Kind               string
	Namespace          string
	ServiceAccountName string
	File               string
	Doc                map[string]interface{}
}

// LoadedResources is the aggregate of all parsed RBAC-relevant resources.
type LoadedResources struct {
	ClusterRoles        map[string]*ClusterRoleData
	Roles               map[string]*RoleData         // key: "namespace/name"
	ClusterRoleBindings []*BindingData
	RoleBindings        []*BindingData
	ServiceAccounts     map[string]*SAData           // key: "namespace/name"
	Pods                map[string]*PodData          // key: "namespace/name"
	Workloads           map[string]*WorkloadData     // key: "namespace/name"
}

// NewLoadedResources creates an initialized LoadedResources with empty maps/slices.
func NewLoadedResources() *LoadedResources {
	return &LoadedResources{
		ClusterRoles:        make(map[string]*ClusterRoleData),
		Roles:               make(map[string]*RoleData),
		ClusterRoleBindings: nil,
		RoleBindings:        nil,
		ServiceAccounts:     make(map[string]*SAData),
		Pods:                make(map[string]*PodData),
		Workloads:           make(map[string]*WorkloadData),
	}
}

// IsEmpty returns true if no RBAC resources were loaded.
// Workloads and Pods are not considered RBAC resources for this check.
func (r *LoadedResources) IsEmpty() bool {
	return len(r.ClusterRoles) == 0 &&
		len(r.Roles) == 0 &&
		len(r.ClusterRoleBindings) == 0 &&
		len(r.RoleBindings) == 0 &&
		len(r.ServiceAccounts) == 0 &&
		len(r.Pods) == 0
}
