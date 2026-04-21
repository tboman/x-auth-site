package internal

import (
	"fmt"
	"strings"
)

// Supported policy fields. These are the only paths a rule condition can
// address in phase 1 — any other value is rejected at policy write time.
const (
	FieldAction              = "action"
	FieldResource            = "resource"
	FieldResourceSensitivity = "resource_sensitivity"
	FieldUserID              = "user_id"
	FieldContextIPAddress    = "context.ip_address"
	FieldContextCountry      = "context.country"
)

// Supported policy operators. `eq` and `in` are exact match; `gt` is numeric;
// `contains` is case-sensitive substring on strings.
const (
	OpEq       = "eq"
	OpIn       = "in"
	OpGt       = "gt"
	OpContains = "contains"
)

// PolicyEvalResult is what the engine hands back to the caller. DerivedTier is
// the aggregator's tier (before any floor); EffectiveTier is after any
// matching tier_floor has been applied. Decision is allow unless a matching
// rule denied.
type PolicyEvalResult struct {
	DerivedTier     string
	EffectiveTier   string
	Decision        string
	MatchedPolicies []string
}

// EvaluatePolicies walks every tenant-scoped policy and applies each rule to
// req. A matching rule with Deny=true short-circuits the decision to deny;
// all other matches contribute tier_floor candidates, and the highest floor
// wins.
//
// Policies are evaluated in the order ListPolicies returns them (sorted by
// CreatedAt). The order is observable only through MatchedPolicies — the
// decision itself is order-independent because deny wins globally and
// tier_floor uses max().
func EvaluatePolicies(req EvaluateRequest, derivedTier string, policies []Policy) PolicyEvalResult {
	result := PolicyEvalResult{
		DerivedTier:     derivedTier,
		EffectiveTier:   derivedTier,
		Decision:        DecisionAllow,
		MatchedPolicies: nil,
	}

	highestFloorRank := tierRank(derivedTier)
	highestFloor := derivedTier

	for _, p := range policies {
		policyMatched := false
		for _, rule := range p.Rules {
			if !matchesCondition(req, rule.Condition) {
				continue
			}
			policyMatched = true
			if rule.Action.Deny {
				result.Decision = DecisionDeny
			}
			if rule.Action.TierFloor != "" {
				rank := tierRank(rule.Action.TierFloor)
				if rank > highestFloorRank {
					highestFloorRank = rank
					highestFloor = rule.Action.TierFloor
				}
			}
		}
		if policyMatched {
			result.MatchedPolicies = append(result.MatchedPolicies, p.ID)
		}
	}

	result.EffectiveTier = highestFloor
	return result
}

// matchesCondition is the per-rule dispatcher. Missing request fields are
// treated as empty strings/zero values — a rule matching an absent field with
// `eq ""` will fire, which is intentional (lets operators write rules that
// catch malformed traffic).
func matchesCondition(req EvaluateRequest, c PolicyCondition) bool {
	got := fieldValue(req, c.Field)
	switch c.Op {
	case OpEq:
		return equalAny(got, c.Value)
	case OpIn:
		return inList(got, c.Value)
	case OpContains:
		s, ok := got.(string)
		if !ok {
			return false
		}
		sub, ok := c.Value.(string)
		if !ok {
			return false
		}
		return strings.Contains(s, sub)
	case OpGt:
		gotN, ok := toNumber(got)
		if !ok {
			return false
		}
		wantN, ok := toNumber(c.Value)
		if !ok {
			return false
		}
		return gotN > wantN
	}
	return false
}

// fieldValue resolves a dotted field name against the request. Unknown fields
// return an empty string so the caller can still run op comparisons without
// special-casing — they just won't match anything meaningful.
func fieldValue(req EvaluateRequest, field string) any {
	switch field {
	case FieldAction:
		return req.Action
	case FieldResource:
		return req.Resource
	case FieldResourceSensitivity:
		return req.ResourceSensitivity
	case FieldUserID:
		return req.UserID
	case FieldContextIPAddress:
		return req.Context.IPAddress
	case FieldContextCountry:
		return req.Context.Country
	}
	return ""
}

// equalAny compares two values with a light type-tolerant strategy: strings
// compare as strings, numbers as float64 (so JSON's int-vs-float ambiguity
// doesn't bite), everything else via fmt.Sprintf.
func equalAny(a, b any) bool {
	if a == nil || b == nil {
		return a == b
	}
	if sa, ok := a.(string); ok {
		if sb, ok := b.(string); ok {
			return sa == sb
		}
	}
	if na, ok := toNumber(a); ok {
		if nb, ok := toNumber(b); ok {
			return na == nb
		}
	}
	return fmt.Sprintf("%v", a) == fmt.Sprintf("%v", b)
}

// inList returns true if a equals any element of list. list must be a JSON
// array ([]any); anything else fails closed (returns false).
func inList(a, list any) bool {
	arr, ok := list.([]any)
	if !ok {
		return false
	}
	for _, v := range arr {
		if equalAny(a, v) {
			return true
		}
	}
	return false
}

// toNumber normalises JSON numbers (all float64) and Go ints to float64.
func toNumber(v any) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case float32:
		return float64(n), true
	case int:
		return float64(n), true
	case int32:
		return float64(n), true
	case int64:
		return float64(n), true
	}
	return 0, false
}

// ValidateRules checks every rule's field and op against the supported set.
// Called on policy Create and Update so bad rules never land in storage.
func ValidateRules(rules []PolicyRule) error {
	if len(rules) == 0 {
		return fmt.Errorf("at least one rule is required")
	}
	if len(rules) > MaxRulesPerPolicy {
		return fmt.Errorf("a policy may have at most %d rules", MaxRulesPerPolicy)
	}
	for i, r := range rules {
		if err := validateRule(r); err != nil {
			return fmt.Errorf("rule[%d]: %w", i, err)
		}
	}
	return nil
}

func validateRule(r PolicyRule) error {
	switch r.Condition.Field {
	case FieldAction, FieldResource, FieldResourceSensitivity,
		FieldUserID, FieldContextIPAddress, FieldContextCountry:
	default:
		return fmt.Errorf("unsupported field %q", r.Condition.Field)
	}
	switch r.Condition.Op {
	case OpEq, OpIn, OpContains, OpGt:
	default:
		return fmt.Errorf("unsupported op %q", r.Condition.Op)
	}
	if r.Condition.Op == OpIn {
		if _, ok := r.Condition.Value.([]any); !ok {
			return fmt.Errorf("op \"in\" requires an array value")
		}
	}
	if !r.Action.Deny && r.Action.TierFloor == "" {
		return fmt.Errorf("rule action must set either deny or tier_floor")
	}
	if r.Action.TierFloor != "" && !ValidTier(r.Action.TierFloor) {
		return fmt.Errorf("invalid tier_floor %q", r.Action.TierFloor)
	}
	return nil
}
