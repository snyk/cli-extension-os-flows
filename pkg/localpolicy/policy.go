package localpolicy

import (
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

const specVersion = "v1.25.1"

// New returns a pointer to a Policy, which will be prepopulated with a version
// and non-nil maps. This is the preferred way to create a new policy from scratch.
func New() *Policy {
	return &Policy{
		Version: specVersion,
		Ignore:  make(RuleSet),
		Patch:   make(RuleSet),
	}
}

// Unmarshal reads a policy from r into target.
//
// A file with nothing to parse - empty, whitespace, or comments only - leaves
// target untouched and reports no error, matching the legacy CLI, which treats
// such a file as an absent policy rather than a failure.
func Unmarshal(r io.Reader, target *Policy) error {
	data, err := io.ReadAll(r)
	if err != nil {
		return fmt.Errorf("failed to read snyk policy: %w", err)
	}

	if err := yaml.Unmarshal(data, target); err != nil {
		// The legacy YAML reader accepts a tab as indentation where the spec
		// does not. Retry once with leading tabs expanded so a tab-indented
		// file still loads, while genuinely malformed YAML stays fatal.
		if expanded, ok := expandLeadingTabs(data); ok {
			if retryErr := yaml.Unmarshal(expanded, target); retryErr == nil {
				return nil
			}
		}
		return fmt.Errorf("failed to decode snyk policy: %w", err)
	}
	return nil
}

// expandLeadingTabs replaces tabs in each line's indentation with spaces. The
// second return value reports whether any line was actually indented with a
// tab; when it is false the caller has nothing to retry.
func expandLeadingTabs(data []byte) ([]byte, bool) {
	lines := strings.Split(string(data), "\n")
	found := false

	for i, line := range lines {
		indent := len(line) - len(strings.TrimLeft(line, " \t"))
		if !strings.ContainsRune(line[:indent], '\t') {
			continue
		}
		found = true
		lines[i] = strings.ReplaceAll(line[:indent], "\t", "  ") + line[indent:]
	}

	if !found {
		return nil, false
	}
	return []byte(strings.Join(lines, "\n")), true
}

// Marshal writes a serialized policy to w.
func Marshal(w io.Writer, p *Policy) error {
	if err := yaml.NewEncoder(w).Encode(p); err != nil {
		return fmt.Errorf("failed to encode snyk policy: %w", err)
	}
	return nil
}

// Load loads a policy from a given file path.
func Load(path string) (*Policy, error) {
	fd, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open policy file: %w", err)
	}
	defer fd.Close()
	var p Policy
	if err := Unmarshal(fd, &p); err != nil {
		return nil, fmt.Errorf("failed to load policy: %w", err)
	}
	return &p, nil
}

// Policy models the legacy .snyk policy.
type Policy struct {
	Version       string          `yaml:"version"`
	FailThreshold *Severity       `yaml:"failThreshold,omitempty"`
	Ignore        RuleSet         `yaml:"ignore"`
	Patch         RuleSet         `yaml:"patch"`
	Exclude       *map[string]any `yaml:"exclude,omitempty"`
}

// UnmarshalYAML decodes a Policy, tolerating a document that is not a mapping.
// Legacy accepts a bare scalar or a sequence in .snyk and carries on with no
// policy, so a junk document must not fail the whole test.
func (p *Policy) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind != yaml.MappingNode {
		return nil
	}

	// A distinct type breaks the recursion back into this method.
	type policyShadow Policy
	var shadow policyShadow
	if err := node.Decode(&shadow); err != nil {
		return fmt.Errorf("failed to decode policy: %w", err)
	}

	*p = Policy(shadow)
	return nil
}

// Severity models an issues severity level.
type Severity string

const (
	//nolint:revive // Severity levels are self-explanatory.
	SeverityLow      = Severity("low")
	SeverityMedium   = Severity("medium")
	SeverityHigh     = Severity("high")
	SeverityCritical = Severity("critical")
)

// VulnID models the unique identifier of a Snyk vulnerability.
type VulnID string

// RuleSet models rules grouped by vulnerability identifiers.
type RuleSet map[VulnID][]RuleEntry

// UnmarshalYAML accepts an empty sequence, empty mapping, or null as an empty RuleSet.
func (r *RuleSet) UnmarshalYAML(node *yaml.Node) error {
	switch node.Kind {
	case yaml.MappingNode:
		var m map[VulnID][]RuleEntry
		if err := node.Decode(&m); err != nil {
			return fmt.Errorf("failed to decode rule set: %w", err)
		}
		*r = m
		return nil
	case yaml.SequenceNode:
		if len(node.Content) == 0 {
			*r = RuleSet{}
			return nil
		}
		return fmt.Errorf("line %d: rule set must be a mapping, got a non-empty sequence", node.Line)
	case yaml.ScalarNode:
		if node.Tag == "!!null" || node.Value == "" {
			*r = RuleSet{}
			return nil
		}
		return fmt.Errorf("line %d: rule set must be a mapping, got scalar %q", node.Line, node.Value)
	default:
		return fmt.Errorf("line %d: rule set has unsupported YAML kind %d", node.Line, node.Kind)
	}
}

// RuleEntry models rules grouped by the dependency path.
type RuleEntry map[string]*Rule

// UnmarshalYAML decodes a RuleEntry, substituting an empty rule for a null rule
// body. `- '*':` with nothing under it is an ignore with no reason and no
// expiry in legacy; leaving the pointer nil would hand a nil rule to every
// consumer of the policy.
func (re *RuleEntry) UnmarshalYAML(node *yaml.Node) error {
	var rules map[string]*Rule
	if err := node.Decode(&rules); err != nil {
		return fmt.Errorf("failed to decode rule entry: %w", err)
	}

	for path, rule := range rules {
		if rule == nil {
			rules[path] = &Rule{}
		}
	}

	*re = rules
	return nil
}

// Rule models an actual policy rule.
type Rule struct {
	Created            *time.Time  `yaml:"created,omitempty"`
	Expires            *time.Time  `yaml:"expires,omitempty"`
	Patched            *time.Time  `yaml:"patched,omitempty"`
	IgnoredBy          *IgnoredBy  `yaml:"ignoredBy,omitempty"`
	Reason             *string     `yaml:"reason,omitempty"`
	ReasonType         *ReasonType `yaml:"reasonType,omitempty"`
	Source             *string     `yaml:"source,omitempty"`
	From               *string     `yaml:"from,omitempty"`
	DisregardIfFixable *bool       `yaml:"disregardIfFixable,omitempty"`
}

var lenientTimeFormats = []string{
	time.RFC3339Nano,
	time.RFC3339,
	"2006-01-02T15:04:05.999999999",
	"2006-01-02 15:04:05.999999999",
	"2006-01-02",
}

type lenientTime struct {
	t *time.Time
}

// UnmarshalYAML parses a timestamp in any of the supported layouts. A value it
// cannot parse is left unset rather than rejected: legacy applies such a rule
// with no expiry instead of failing the file, and an ignore that silently loses
// its expiry is a smaller surprise than a scan that refuses to run.
func (lt *lenientTime) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind != yaml.ScalarNode || node.Tag == "!!null" || node.Value == "" {
		return nil
	}
	for _, layout := range lenientTimeFormats {
		if parsed, err := time.Parse(layout, node.Value); err == nil {
			lt.t = &parsed
			return nil
		}
	}
	return nil
}

// UnmarshalYAML decodes a Rule with lenient parsing for timestamp fields.
func (r *Rule) UnmarshalYAML(node *yaml.Node) error {
	var shadow struct {
		Created            lenientTime `yaml:"created,omitempty"`
		Expires            lenientTime `yaml:"expires,omitempty"`
		Patched            lenientTime `yaml:"patched,omitempty"`
		IgnoredBy          *IgnoredBy  `yaml:"ignoredBy,omitempty"`
		Reason             *string     `yaml:"reason,omitempty"`
		ReasonType         *ReasonType `yaml:"reasonType,omitempty"`
		Source             *string     `yaml:"source,omitempty"`
		From               *string     `yaml:"from,omitempty"`
		DisregardIfFixable *bool       `yaml:"disregardIfFixable,omitempty"`
	}
	if err := node.Decode(&shadow); err != nil {
		return fmt.Errorf("failed to decode rule: %w", err)
	}
	r.Created = shadow.Created.t
	r.Expires = shadow.Expires.t
	r.Patched = shadow.Patched.t
	r.IgnoredBy = shadow.IgnoredBy
	r.Reason = shadow.Reason
	r.ReasonType = shadow.ReasonType
	r.Source = shadow.Source
	r.From = shadow.From
	r.DisregardIfFixable = shadow.DisregardIfFixable
	return nil
}

// IgnoredBy models the user who applied a project-level ignore.
type IgnoredBy struct {
	Email *string `yaml:"email,omitempty"`
	Name  *string `yaml:"name,omitempty"`
	ID    *string `yaml:"id,omitempty"`
}

// ReasonType is an enum of known categories for why a rule was applied.
type ReasonType string

const (
	// ReasonTypeNotVulnerable applies if an issue does not apply.
	ReasonTypeNotVulnerable = ReasonType("not-vulnerable")
	// ReasonTypeWontFix applies if an issue is intentionally being ignored.
	ReasonTypeWontFix = ReasonType("wont-fix")
	// ReasonTypeTemporaryIgnore applies if an issue is being ignored temporarily.
	ReasonTypeTemporaryIgnore = ReasonType("temporary-ignore")
)
