package internal

// deriveAssurance maps a verified mdoc outcome to an assurance tier plus the
// signals that produced it. The tier mirrors the green/amber/red language used
// across the sites:
//
//   - high   issuer chain anchored to a trusted IACA root AND device-bound
//   - medium device-bound (proof of possession) but issuer chain not anchored
//   - low    structural only (no device binding)
func deriveAssurance(o *mdocOutcome) (string, []string) {
	signals := append([]string{}, o.signals...)
	if o.issuerTrusted {
		signals = append(signals, "issuer_trusted")
	} else {
		signals = append(signals, "issuer_untrusted")
	}

	switch {
	case o.issuerTrusted && o.deviceBound:
		return AssuranceHigh, signals
	case o.deviceBound:
		return AssuranceMedium, signals
	default:
		return AssuranceLow, signals
	}
}
