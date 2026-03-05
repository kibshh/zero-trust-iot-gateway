package policy

// RuleSource provides ZTPV rules for a given device.
// This abstraction allows rules to come from static config, a database,
// or a per-device override store without changing the service layer.
type RuleSource interface {
	// RulesFor returns the set of rules to embed in the ZTPV policy for deviceID.
	// Implementations must return at least one rule or an error.
	RulesFor(deviceID string) ([]ZTPVRule, error)
}

// StaticRuleSource returns the same fixed rule set for every device.
// Intended for development and initial bring-up.
type StaticRuleSource struct {
	rules []ZTPVRule
}

// NewStaticRuleSource creates a RuleSource that always returns the given rules.
func NewStaticRuleSource(rules []ZTPVRule) *StaticRuleSource {
	return &StaticRuleSource{rules: rules}
}

// NewDefaultRuleSource returns a StaticRuleSource pre-loaded with DefaultRuntimeRules.
func NewDefaultRuleSource() *StaticRuleSource {
	return NewStaticRuleSource(DefaultRuntimeRules())
}

func (s *StaticRuleSource) RulesFor(_ string) ([]ZTPVRule, error) {
	if len(s.rules) == 0 {
		return nil, ErrZTPVNoRules
	}
	return s.rules, nil
}
