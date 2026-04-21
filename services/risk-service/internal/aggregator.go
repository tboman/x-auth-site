package internal

import "context"

// Aggregate runs every scorer, applies the weighted sum, overlays resource
// sensitivity, and returns the aggregate score plus the per-scorer breakdown.
// It does *not* apply policy — the handler does that after deriving the tier
// so matching rules can observe the pre-policy tier.
//
// The scorer list is fixed for phase 1: exactly the four scorers in the
// pipeline diagram (ARCHITECTURE.md §7.1). Adding a fifth scorer later means
// introducing a fifth weight and re-normalising — not a trivial change, so it
// stays hard-coded until a concrete need arises.
func Aggregate(
	ctx context.Context,
	req EvaluateRequest,
	tenantID string,
	store Storage,
	clock Clock,
) (signals SignalsBreakdown, aggregate float64) {
	signals.Device = DeviceScorer(ctx, req, tenantID, store, clock)
	signals.Behavior = BehaviorScorer(ctx, req, tenantID, store, clock)
	signals.Network = NetworkScorer(ctx, req, tenantID, store, clock)
	signals.User = UserScorer(ctx, req, tenantID, store, clock)

	weighted := signals.Device.Score*WeightDevice +
		signals.Behavior.Score*WeightBehavior +
		signals.Network.Score*WeightNetwork +
		signals.User.Score*WeightUser

	weighted = clamp01(weighted)
	weighted = applySensitivity(weighted, req.ResourceSensitivity)
	return signals, weighted
}

// applySensitivity multiplies score by the per-level multiplier and clamps
// back to [0, 1]. Unknown levels pass through unchanged — callers validate
// resource_sensitivity before calling us, but keeping this permissive here
// avoids a panic if a bad value ever slips past validation.
func applySensitivity(score float64, level string) float64 {
	var m float64
	switch level {
	case SensitivityLow:
		m = SensitivityMultLow
	case SensitivityMedium:
		m = SensitivityMultMedium
	case SensitivityHigh:
		m = SensitivityMultHigh
	default:
		m = SensitivityMultLow
	}
	return clamp01(score * m)
}

// DeriveTier maps a final score to low/medium/high using the thresholds from
// the implementation spec:
//
//	score <  0.35            → low
//	0.35 ≤ score ≤ 0.70      → medium
//	score >  0.70            → high
//
// The boundary convention (inclusive at the bottom, inclusive at the top of
// medium) matches the "< 0.35", "0.35–0.7", "> 0.7" wording of the spec.
func DeriveTier(score float64) string {
	switch {
	case score < TierLowMax:
		return TierLow
	case score <= TierMediumMax:
		return TierMedium
	default:
		return TierHigh
	}
}

// collectFlags flattens per-scorer flags into a single slice in a stable
// order (device → behavior → network → user). Stable ordering keeps
// responses easy to test and grep-friendly in logs.
func collectFlags(s SignalsBreakdown) []string {
	out := make([]string, 0, len(s.Device.Flags)+len(s.Behavior.Flags)+len(s.Network.Flags)+len(s.User.Flags))
	out = append(out, s.Device.Flags...)
	out = append(out, s.Behavior.Flags...)
	out = append(out, s.Network.Flags...)
	out = append(out, s.User.Flags...)
	return out
}
