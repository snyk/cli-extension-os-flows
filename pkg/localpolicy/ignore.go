package localpolicy

import "strings"

// AddIgnore appends an ignore rule for a given vulnerability ID.
func (p *Policy) AddIgnore(vulnID VulnID, path []string, rule *Rule) {
	pathStr := "*"
	if len(path) > 0 {
		pathStr = strings.Join(path, " > ")
	}

	p.Ignore[vulnID] = append(p.Ignore[vulnID], RuleEntry{pathStr: rule})
}
